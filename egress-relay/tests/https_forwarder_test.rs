mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use common::{
    client_tls_config, collect_body, issue_upstream_certificate, safe_resolver_for,
    server_tls_config, Issued, PinnedResolver,
};
use egress_relay::https_forwarder::{build_egress_client, HttpsForwarder};
use egress_relay::https_relay::{ForwardError, ForwardRequest, Forwarder};
use egress_relay::relay_resolver::SafeResolver;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Minimal HTTP/1.1-over-TLS upstream. It asserts the projected request line,
/// business header and body arrived, then writes back the supplied response and
/// counts how many TCP connections it accepted.
async fn spawn_https_upstream(
    issued: Issued,
    response: &'static [u8],
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(issued)));
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        counter.fetch_add(1, Ordering::SeqCst);
        let mut stream = acceptor.accept(stream).await.unwrap();

        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "client closed before request headers were sent");
            request.extend_from_slice(&chunk[..read]);
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        while request.len() < header_end + b"payload".len() {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "client closed before request body was sent");
            request.extend_from_slice(&chunk[..read]);
        }

        assert!(
            request.starts_with(b"POST /v1/responses?q=1 HTTP/1.1\r\n"),
            "unexpected request line: {:?}",
            String::from_utf8_lossy(&request[..header_end])
        );
        assert!(
            request
                .windows(b"x-request-id: fixture".len())
                .any(|window| window == b"x-request-id: fixture"),
            "projected business header missing"
        );
        assert_eq!(
            &request[header_end..header_end + b"payload".len()],
            b"payload"
        );

        stream.write_all(response).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    (address, accepts)
}

fn post_fixture(target: &str) -> ForwardRequest {
    ForwardRequest {
        method: "POST".to_owned(),
        target: target.to_owned(),
        headers: vec![["x-request-id".to_owned(), "fixture".to_owned()]],
        body: Bytes::from_static(b"payload"),
    }
}

#[tokio::test]
async fn rejects_non_https_target_before_network_access() {
    let client = build_egress_client(client_tls_config(None), Arc::new(SafeResolver::system()), 5);
    let forwarder = HttpsForwarder::new(client);

    let result = forwarder
        .forward(post_fixture("http://api.example.com/v1/responses"))
        .await;

    assert!(matches!(result, Err(ForwardError::InvalidTarget)));
}

#[tokio::test]
async fn forwards_method_target_headers_and_body_over_https() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (upstream, accepts) = spawn_https_upstream(
        issued,
        b"HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: 8\r\nconnection: close\r\n\r\nupstream",
    )
    .await;

    let client = build_egress_client(
        client_tls_config(Some(trusted)),
        Arc::new(PinnedResolver(upstream)),
        5,
    );
    let forwarder = HttpsForwarder::new(client);

    let response = forwarder
        .forward(post_fixture("https://api.example.com/v1/responses?q=1"))
        .await
        .unwrap();

    assert_eq!(response.status, reqwest::StatusCode::CREATED);
    let body = collect_body(response.body).await.unwrap();
    assert_eq!(body, Bytes::from_static(b"upstream"));
    assert_eq!(response.headers["content-type"], "application/json");
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn does_not_follow_upstream_redirects() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (upstream, _accepts) = spawn_https_upstream(
        issued,
        b"HTTP/1.1 302 Found\r\nlocation: https://evil.example.com/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    )
    .await;

    let client = build_egress_client(
        client_tls_config(Some(trusted)),
        Arc::new(PinnedResolver(upstream)),
        5,
    );
    let forwarder = HttpsForwarder::new(client);

    let response = forwarder
        .forward(post_fixture("https://api.example.com/v1/responses?q=1"))
        .await
        .unwrap();

    assert_eq!(response.status, reqwest::StatusCode::FOUND);
    assert_eq!(response.headers["location"], "https://evil.example.com/");
}

#[tokio::test]
async fn refuses_hostname_resolving_to_loopback_without_connecting() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (upstream, accepts) = spawn_https_upstream(
        issued,
        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    )
    .await;

    // The real SafeResolver, fed a DNS answer that points at the local upstream.
    let resolver = safe_resolver_for(vec![upstream.ip()]);
    let client = build_egress_client(client_tls_config(Some(trusted)), Arc::new(resolver), 5);
    let forwarder = HttpsForwarder::new(client);

    let result = forwarder
        .forward(post_fixture("https://api.example.com/v1/responses?q=1"))
        .await;

    assert!(result.is_err(), "loopback answer must not be forwarded");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "SSRF policy must reject before any TCP connect"
    );
}
