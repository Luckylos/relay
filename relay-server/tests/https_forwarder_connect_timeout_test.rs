//! A TCP connect that never completes must be cut by its own budget.
//!
//! Every other deadline in the forwarder starts counting once a connection
//! exists: the response-header deadline waits for a status line, the stall
//! budget waits for the next chunk. Neither can fire while the socket is still
//! being opened, so a target whose SYN goes unanswered is bounded only by the
//! 600s overall ceiling.
//!
//! Target validation cannot prevent this. An attacker-chosen hostname may
//! resolve to a public address that passes every SSRF check and then simply
//! never complete a handshake. Each such request pins a relay task and a
//! connection slot for ten minutes -- a cheap way to exhaust the relay long
//! before any other limit notices.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use codex_https_relay::https_forwarder::{build_egress_client_with_timeouts, HttpsForwarder};
use codex_https_relay::https_relay::{ForwardError, ForwardRequest, Forwarder};
use common::{client_tls_config, PinnedResolver};
use tokio::net::TcpListener;

/// A listener that accepts nothing, with a full accept queue.
///
/// Once the queue overflows, Linux silently drops further SYNs (the default
/// `tcp_abort_on_overflow=0`), so a client's `connect` hangs in SYN-retransmit
/// instead of being refused. That reproduces an unresponsive upstream using only
/// loopback -- no reliance on a reserved address being unrouted, which a
/// transparent proxy on the host may quietly intercept and answer.
async fn spawn_black_hole() -> (SocketAddr, Vec<tokio::net::TcpStream>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();

    // Fill the accept queue. These sockets are returned so they stay open for
    // the lifetime of the test; dropping them would free the queue.
    let mut queued = Vec::new();
    for _ in 0..8 {
        match tokio::time::timeout(
            Duration::from_millis(200),
            tokio::net::TcpStream::connect(address),
        )
        .await
        {
            Ok(Ok(stream)) => queued.push(stream),
            // Already saturated: further connects now hang, which is the state
            // the test needs.
            _ => break,
        }
    }

    // The listener is deliberately never polled for `accept`, and is leaked for
    // the duration of the test so the port stays bound without draining.
    std::mem::forget(listener);
    (address, queued)
}

fn forward_request(target: &str) -> ForwardRequest {
    ForwardRequest {
        method: "GET".to_owned(),
        target: target.to_owned(),
        headers: Vec::new(),
        body: bytes::Bytes::new(),
    }
}

#[tokio::test]
async fn a_connect_that_never_completes_is_cut_by_the_connect_budget() {
    let (black_hole, _queued) = spawn_black_hole().await;
    let connect_budget = Duration::from_secs(2);

    // Generous everywhere else, so only the connect budget can end this.
    let client = build_egress_client_with_timeouts(
        client_tls_config(None),
        Arc::new(PinnedResolver(black_hole)),
        600,
        600,
        connect_budget.as_secs(),
    );
    let forwarder =
        HttpsForwarder::new(client).with_response_header_timeout(Duration::from_secs(600));

    let started = Instant::now();
    let result = forwarder
        .forward(forward_request(
            "https://black-hole.example.com/v1/responses",
        ))
        .await;
    let elapsed = started.elapsed();

    assert!(
        matches!(
            result,
            Err(ForwardError::Unavailable) | Err(ForwardError::Timeout)
        ),
        "an upstream that never completes a handshake must fail, not hang"
    );
    // The point of the test: bounded by the connect budget, not by the 600s
    // ceiling. The upper bound is loose enough for a slow CI box while staying
    // far below any other deadline that could have produced the failure.
    assert!(
        elapsed < Duration::from_secs(20),
        "connect took {elapsed:?}; the connect budget did not bound it"
    );
}
