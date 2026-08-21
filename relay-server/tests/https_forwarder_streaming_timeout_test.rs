//! A relayed SSE turn must survive an upstream that thinks for longer than the
//! response-header deadline, and must keep surviving between chunks.
//!
//! Reasoning models routinely spend tens of seconds before the first token, then
//! emit sparse keep-alives. reqwest documents `read_timeout` as applying to
//! *each read operation*, and attaches it to the response body, so a single
//! short value silently doubles as "max first-token wait" *and* "max gap between
//! SSE chunks". The stall budget therefore has to be configurable independently
//! of the header deadline.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use codex_https_relay::https_forwarder::{build_egress_client_with_timeouts, HttpsForwarder};
use codex_https_relay::https_relay::{ForwardRequest, Forwarder};
use common::{
    client_tls_config, collect_body, issue_upstream_certificate, server_tls_config, Issued,
    PinnedResolver,
};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// An upstream that stalls `think` before the status line, then writes each SSE
/// chunk `gap` apart. This is the shape of a real reasoning turn.
async fn spawn_slow_sse_upstream(
    issued: Issued,
    think: Duration,
    gap: Duration,
    chunks: usize,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_config(issued)));
    let delivered = Arc::new(AtomicUsize::new(0));
    let counter = delivered.clone();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();

        let mut request = Vec::new();
        loop {
            let mut buf = [0_u8; 1024];
            let read = stream.read(&mut buf).await.unwrap();
            assert!(read > 0, "client closed before sending request headers");
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        // Think before answering at all: this is what a reasoning model does.
        tokio::time::sleep(think).await;

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  content-type: text/event-stream\r\n\
                  transfer-encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        stream.flush().await.unwrap();

        for index in 0..chunks {
            tokio::time::sleep(gap).await;
            let payload = format!("data: {{\"i\":{index}}}\n\n");
            if stream
                .write_all(format!("{:x}\r\n{payload}\r\n", payload.len()).as_bytes())
                .await
                .is_err()
            {
                return;
            }
            if stream.flush().await.is_err() {
                return;
            }
            counter.fetch_add(1, Ordering::SeqCst);
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
        let _ = stream.flush().await;
    });

    (address, delivered)
}

fn sse_request() -> ForwardRequest {
    ForwardRequest {
        method: "POST".to_owned(),
        target: "https://api.example.com/v1/responses".to_owned(),
        headers: vec![["accept".to_owned(), "text/event-stream".to_owned()]],
        body: bytes::Bytes::from_static(b"{}"),
    }
}

/// The relay must not cut a turn whose first byte arrives after the
/// response-header deadline elapses, when the caller allows a longer stall.
#[tokio::test]
async fn survives_first_token_slower_than_the_header_deadline() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (address, _) =
        spawn_slow_sse_upstream(issued, Duration::from_millis(1_500), Duration::ZERO, 2).await;

    // Header deadline deliberately shorter than the upstream's thinking time,
    // while the stall budget is generous. Today these are the same knob, so the
    // short value also governs the body read and the turn dies.
    let client = build_egress_client_with_timeouts(
        client_tls_config(Some(trusted)),
        Arc::new(PinnedResolver(address)),
        600,
        30, // stall budget between reads: generous
        30, // connect: not under test, the pinned upstream accepts at once
    );
    // Header deadline deliberately shorter than the upstream's think time.
    let forwarder =
        HttpsForwarder::new(client).with_response_header_timeout(Duration::from_secs(3));

    let response = forwarder
        .forward(sse_request())
        .await
        .expect("a slow first token must not fail the turn");
    assert_eq!(response.status, 200);

    let body = collect_body(response.body).await.expect("body");
    assert!(
        String::from_utf8_lossy(&body).contains("\"i\":0"),
        "expected SSE payload, got {:?}",
        String::from_utf8_lossy(&body)
    );
}

/// A long quiet gap *between* SSE chunks must also be tolerated up to the stall
/// budget, not cut at the header deadline.
#[tokio::test]
async fn survives_quiet_gaps_between_sse_chunks() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (address, delivered) =
        spawn_slow_sse_upstream(issued, Duration::ZERO, Duration::from_millis(1_200), 3).await;

    let client = build_egress_client_with_timeouts(
        client_tls_config(Some(trusted)),
        Arc::new(PinnedResolver(address)),
        600,
        30, // gaps up to 30s are legitimate keep-alive silence
        30, // connect: not under test, the pinned upstream accepts at once
    );
    // Tight header deadline must not leak into the body's chunk gaps.
    let forwarder =
        HttpsForwarder::new(client).with_response_header_timeout(Duration::from_secs(1));

    let response = forwarder.forward(sse_request()).await.expect("forward");
    let body = collect_body(response.body)
        .await
        .expect("all chunks must arrive despite the gaps");

    let text = String::from_utf8_lossy(&body);
    for index in 0..3 {
        assert!(
            text.contains(&format!("\"i\":{index}")),
            "chunk {index} missing from {text:?}"
        );
    }
    assert_eq!(delivered.load(Ordering::SeqCst), 3);
}

/// The stall budget must still be enforced: an upstream that goes permanently
/// silent mid-stream has to be cut, or it pins a relay connection forever.
#[tokio::test]
async fn still_cuts_a_stream_that_stalls_past_the_budget() {
    let issued = issue_upstream_certificate();
    let trusted = issued.certificate.clone();
    let (address, _) = spawn_slow_sse_upstream(
        issued,
        Duration::ZERO,
        Duration::from_secs(30), // far beyond the 1s budget below
        2,
    )
    .await;

    let client = build_egress_client_with_timeouts(
        client_tls_config(Some(trusted)),
        Arc::new(PinnedResolver(address)),
        600,
        1,  // stall budget: 1s
        30, // connect: not under test, the pinned upstream accepts at once
    );
    let forwarder =
        HttpsForwarder::new(client).with_response_header_timeout(Duration::from_secs(5));

    let response = forwarder
        .forward(sse_request())
        .await
        .expect("headers arrive before the stall");
    let outcome = collect_body(response.body).await;
    assert!(
        outcome.is_err(),
        "a permanently silent upstream must not be relayed indefinitely"
    );
}
