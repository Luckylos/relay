//! Slice 5: the relay must stream upstream response bodies instead of buffering
//! them, or SSE from the Responses API arrives only after the turn ends.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use codex_egress_relay::https_forwarder::{
    build_egress_client, build_egress_client_with_timeouts, HttpsForwarder,
};
use codex_egress_relay::https_relay::{ForwardRequest, Forwarder};
use common::{
    client_tls_config, http_chunk, issue_upstream_certificate, server_tls_config, Issued,
};
use futures_util::StreamExt;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// SSE upstream that emits one event, then blocks until the test releases it.
/// A forwarder that buffers the whole body cannot hand back the first event
/// while this task is still parked, so the first-chunk assertion below is only
/// satisfiable by real streaming.
async fn spawn_blocking_sse_upstream(issued: Issued) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(issued)));
    let (release, released) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();

        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "client closed before sending request headers");
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  content-type: text/event-stream\r\n\
                  transfer-encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        stream
            .write_all(&http_chunk(b"data: one\n\n"))
            .await
            .unwrap();
        stream.flush().await.unwrap();

        // Park mid-body. Nothing more reaches the wire until the test says so.
        released.await.ok();

        stream
            .write_all(&http_chunk(b"data: two\n\n"))
            .await
            .unwrap();
        stream.write_all(b"0\r\n\r\n").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.ok();
    });

    (address, release)
}

fn get_fixture() -> ForwardRequest {
    ForwardRequest {
        method: "GET".to_owned(),
        target: "https://api.example.com/v1/responses?stream=true".to_owned(),
        headers: vec![["accept".to_owned(), "text/event-stream".to_owned()]],
        body: Bytes::new(),
    }
}

#[tokio::test]
async fn streams_first_chunk_before_the_upstream_finishes_the_body() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (upstream, release) = spawn_blocking_sse_upstream(issued).await;

    let client = build_egress_client(
        client_tls_config(Some(trusted)),
        Arc::new(common::PinnedResolver(upstream)),
        5,
    );
    let forwarder = HttpsForwarder::new(client);

    let mut response = forwarder.forward(get_fixture()).await.unwrap();
    assert_eq!(response.status, reqwest::StatusCode::OK);
    assert_eq!(response.headers["content-type"], "text/event-stream");

    let first = tokio::time::timeout(Duration::from_secs(2), response.body.next())
        .await
        .expect("first SSE event must arrive while the upstream body is still open")
        .expect("stream ended before the first event")
        .unwrap();
    assert_eq!(first, Bytes::from_static(b"data: one\n\n"));

    release.send(()).unwrap();

    let second = tokio::time::timeout(Duration::from_secs(2), response.body.next())
        .await
        .expect("second SSE event must arrive after the upstream resumes")
        .expect("stream ended before the second event")
        .unwrap();
    assert_eq!(second, Bytes::from_static(b"data: two\n\n"));

    assert!(
        tokio::time::timeout(Duration::from_secs(2), response.body.next())
            .await
            .expect("stream must terminate after the last chunk")
            .is_none(),
        "stream must end once the upstream closes the body"
    );
}

/// One-shot upstream that replies with the supplied raw bytes.
async fn spawn_fixed_upstream(issued: Issued, response: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(issued)));

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await.unwrap();
            assert!(read > 0, "client closed before sending request headers");
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream.write_all(response).await.unwrap();
        stream.shutdown().await.ok();
    });

    address
}

fn forwarder_for(
    upstream: SocketAddr,
    trusted: rustls::pki_types::CertificateDer<'static>,
) -> HttpsForwarder {
    HttpsForwarder::new(build_egress_client(
        client_tls_config(Some(trusted)),
        Arc::new(common::PinnedResolver(upstream)),
        5,
    ))
}

#[tokio::test]
async fn strips_connection_scoped_response_headers_but_keeps_content_encoding() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    // `content-length` and `transfer-encoding` describe the upstream connection's
    // framing, not ours; re-emitting them alongside a re-framed stream produces a
    // response the client cannot parse. `content-encoding` is payload semantics
    // and MUST survive, because the relay never decompresses.
    let upstream = spawn_fixed_upstream(
        issued,
        b"HTTP/1.1 200 OK\r\n\
          content-type: text/event-stream\r\n\
          content-encoding: gzip\r\n\
          content-length: 4\r\n\
          connection: keep-alive\r\n\
          keep-alive: timeout=5\r\n\
          transfer-encoding: identity\r\n\
          upgrade: h2c\r\n\
          proxy-connection: keep-alive\r\n\
          trailer: x-late\r\n\
          te: trailers\r\n\
          x-upstream-id: keep-me\r\n\r\n\
          body",
    )
    .await;

    let response = forwarder_for(upstream, trusted)
        .forward(get_fixture())
        .await
        .unwrap();

    assert_eq!(response.headers["content-encoding"], "gzip");
    assert_eq!(response.headers["content-type"], "text/event-stream");
    assert_eq!(response.headers["x-upstream-id"], "keep-me");
    for stripped in [
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
        "trailer",
        "te",
    ] {
        assert!(
            !response.headers.contains_key(stripped),
            "connection-scoped header must not be re-emitted: {stripped}"
        );
    }
}

#[tokio::test]
async fn aborts_the_stream_once_the_response_body_limit_is_exceeded() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    // 12 bytes of body against an 8-byte ceiling: the first chunk is allowed
    // through, then the stream must fail rather than keep relaying. Buffering is
    // not an option — the limit has to be enforced while bytes flow.
    let upstream = spawn_fixed_upstream(
        issued,
        b"HTTP/1.1 200 OK\r\n\
          content-type: application/octet-stream\r\n\
          transfer-encoding: chunked\r\n\r\n\
          6\r\naaaaaa\r\n6\r\nbbbbbb\r\n0\r\n\r\n",
    )
    .await;

    let client = build_egress_client(
        client_tls_config(Some(trusted)),
        Arc::new(common::PinnedResolver(upstream)),
        5,
    );
    let mut response = HttpsForwarder::with_response_limit(client, 8)
        .forward(get_fixture())
        .await
        .unwrap();

    let first = response.body.next().await.unwrap().unwrap();
    assert_eq!(first, Bytes::from_static(b"aaaaaa"));

    let second = response
        .body
        .next()
        .await
        .expect("stream must yield an error, not end cleanly");
    let error = second.expect_err("body exceeding the ceiling must fail the stream");
    assert!(
        error.to_string().contains("response body too large"),
        "unexpected error: {error}"
    );

    assert!(
        response.body.next().await.is_none(),
        "stream must terminate after the limit error"
    );
}

/// Upstream that completes the TLS handshake, reads the request, then never
/// sends a status line.
async fn spawn_silent_upstream(issued: Issued) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(issued)));
    let (hold, held) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut sink = [0_u8; 1024];
        let _ = stream.read(&mut sink).await;
        // Never respond; keep the connection open until the test drops us.
        held.await.ok();
    });

    (address, hold)
}

#[tokio::test]
async fn times_out_on_response_headers_well_before_the_overall_ceiling() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (upstream, _hold) = spawn_silent_upstream(issued).await;

    // Overall ceiling stays long because SSE turns are long; the header deadline
    // is what stops a silent upstream from pinning a connection for that whole
    // window. Both are needed, and they are not the same number.
    let client = build_egress_client_with_timeouts(
        client_tls_config(Some(trusted)),
        Arc::new(common::PinnedResolver(upstream)),
        600,
        1,
    );
    let forwarder = HttpsForwarder::new(client);

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(10), forwarder.forward(get_fixture()))
        .await
        .expect("header timeout must fire long before the overall ceiling");

    assert!(
        matches!(
            result,
            Err(codex_egress_relay::https_relay::ForwardError::Timeout)
        ),
        "silent upstream must map to ForwardError::Timeout"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "header deadline must be independent of the 600s overall ceiling"
    );
}
