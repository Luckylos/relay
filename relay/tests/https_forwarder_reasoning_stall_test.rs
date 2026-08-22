//! Regression coverage for the production 504: a reasoning turn that stalls
//! for longer than the old 30s shared timeout before emitting its status line.

use std::sync::Arc;
use std::time::{Duration, Instant};

use codex_https_relay::https_forwarder::{build_egress_client_with_timeouts, HttpsForwarder};
use codex_https_relay::https_relay::{ForwardRequest, Forwarder};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

mod common;
use common::{
    client_tls_config, collect_body, issue_upstream_certificate, server_tls_config, PinnedResolver,
};

/// An upstream that goes quiet for `delay` before sending its status line,
/// mirroring a model that reasons before emitting its first token.
async fn stalling_upstream(delay: Duration) -> (std::net::SocketAddr, CertificateDer<'static>) {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(issued)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        let mut scratch = [0u8; 4096];
        let _ = tls.read(&mut scratch).await;

        tokio::time::sleep(delay).await;

        let body = "data: {\"delta\":\"ok\"}\n\ndata: [DONE]\n\n";
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
            body.len()
        );
        tls.write_all(head.as_bytes()).await.unwrap();
        tls.write_all(body.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    (addr, trusted)
}

fn sse_request() -> ForwardRequest {
    ForwardRequest {
        method: "POST".to_string(),
        target: "https://api.example.com/v1/chat/completions".to_string(),
        headers: vec![["accept".to_string(), "text/event-stream".to_string()]],
        body: b"{}".to_vec().into(),
    }
}

/// The exact production failure: 35s of pre-header silence used to trip the
/// 30s read_timeout and surface as a 504. It must now stream normally.
#[tokio::test]
async fn reasoning_stall_past_the_old_thirty_second_limit_still_streams() {
    let (addr, trusted) = stalling_upstream(Duration::from_secs(35)).await;

    let client = build_egress_client_with_timeouts(
        client_tls_config(Some(trusted)),
        Arc::new(PinnedResolver(addr)),
        600,
        120,
        // Connect is not under test here: the pinned loopback upstream accepts
        // immediately, so this budget is deliberately generous.
        30,
    );
    let forwarder =
        HttpsForwarder::new(client).with_response_header_timeout(Duration::from_secs(300));

    let started = Instant::now();
    let response = forwarder
        .forward(sse_request())
        .await
        .expect("a 35s reasoning stall must not be reported as a relay failure");
    let waited = started.elapsed();

    assert_eq!(response.status, 200);
    let body = collect_body(response.body).await.unwrap();
    assert!(
        body.windows(6).any(|window| window == b"[DONE]"),
        "the stream must run to completion"
    );
    assert!(
        waited >= Duration::from_secs(35),
        "the relay must really have waited out the stall, not short-circuited: {waited:?}"
    );
}
