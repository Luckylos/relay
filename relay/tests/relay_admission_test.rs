//! Admission control must bound *concurrent upstream work*, not just the
//! header-parsing phase of a request.
//!
//! `RelayState::admission` is documented as holding a permit "for the whole
//! request, including the streamed response body". That claim is the entire
//! basis for the cap being meaningful: the relay's dominant traffic shape is an
//! SSE turn whose headers arrive in milliseconds and whose body then stays open
//! for minutes. If the permit is released when the handler returns its
//! `Response` — before hyper has polled a single body chunk — then the cap
//! bounds nothing that costs anything, and the relay will happily hold an
//! unbounded number of open upstream streams.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use codex_https_relay::https_relay::{
    build_app, ForwardError, ForwardRequest, ForwardResponse, ForwardStream, Forwarder, RelayState,
};
use codex_https_relay::relay_auth::{AuthGate, AuthPolicy, KeyRing};
use futures_util::future::BoxFuture;
use tokio::sync::oneshot;
use tower::ServiceExt;

const NOW: i64 = 1_700_000_000;
const SECRET: &[u8] = b"admission-fixture-secret";

/// A forwarder whose *headers* return at once but whose body stays open until
/// released -- the shape of every real SSE turn.
struct StreamingForwarder {
    admitted: Arc<AtomicUsize>,
    release: Mutex<Option<oneshot::Receiver<()>>>,
}

impl Forwarder for StreamingForwarder {
    fn forward(
        &self,
        _request: ForwardRequest,
    ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>> {
        self.admitted.fetch_add(1, Ordering::SeqCst);
        // Only the first admitted request parks; with a cap of 1 nothing else
        // should ever reach here, so taking the receiver is not a race.
        let released = self.release.lock().unwrap().take();
        Box::pin(async move {
            let body: ForwardStream = match released {
                Some(receiver) => Box::pin(futures_util::stream::once(async move {
                    receiver.await.ok();
                    Ok(Bytes::from_static(b"data: done\n\n"))
                })),
                None => Box::pin(futures_util::stream::once(async move {
                    Ok(Bytes::from_static(b"data: immediate\n\n"))
                })),
            };
            Ok(ForwardResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body,
            })
        })
    }
}

fn app_with(forwarder: Arc<dyn Forwarder>, max_concurrency: usize) -> axum::Router {
    let mut keys = KeyRing::default();
    keys.insert("current", SECRET);
    build_app(
        RelayState::with_clock(
            AuthGate::new(keys, AuthPolicy::new(300)),
            forwarder,
            Arc::new(|| NOW),
        )
        .with_max_concurrency(max_concurrency),
    )
}

/// A response whose body is still streaming is still occupying the relay.
///
/// This is the case the cap exists for. A permit that is released as soon as the
/// status line is produced would let an arbitrary number of SSE turns run
/// concurrently while every `try_acquire` still succeeds -- so the relay would
/// keep accepting work until it dies of memory or file descriptors, which is
/// exactly the unattributable crash `relay_busy` was introduced to prevent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_response_body_keeps_holding_its_admission_permit() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let (release, released) = oneshot::channel::<()>();
    let app = app_with(
        Arc::new(StreamingForwarder {
            admitted: admitted.clone(),
            release: Mutex::new(Some(released)),
        }),
        1,
    );

    // First request: headers are in, body is deliberately NOT consumed, so from
    // the client's point of view this turn is still running.
    let first = app
        .clone()
        .oneshot(common::signed_relay_request(
            "AQEBAQEBAQEBAQEBAQEBAQ",
            SECRET,
            NOW,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        admitted.load(Ordering::SeqCst),
        1,
        "the first request must have reached the forwarder"
    );

    // The single slot is still in use, so this must be refused.
    let second = tokio::time::timeout(
        Duration::from_secs(5),
        app.clone().oneshot(common::signed_relay_request(
            "AgICAgICAgICAgICAgICAg",
            SECRET,
            NOW,
        )),
    )
    .await
    .expect("a saturated relay must answer immediately rather than queue")
    .unwrap();

    assert_eq!(
        second.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a second request must be refused while the first response body is still open"
    );
    assert_eq!(
        second
            .headers()
            .get("x-codex-relay-error")
            .and_then(|value| value.to_str().ok()),
        Some("relay_busy"),
        "the refusal must carry the machine code the Worker maps to 503"
    );
    assert_eq!(
        admitted.load(Ordering::SeqCst),
        1,
        "the refused request must never reach the forwarder"
    );

    // Finish the first turn, then prove the slot is genuinely reusable: a permit
    // that is never returned would wedge the relay shut, which is a worse
    // failure than the one being fixed.
    release.send(()).ok();
    let body = axum::body::to_bytes(first.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(body, Bytes::from_static(b"data: done\n\n"));

    let third = tokio::time::timeout(
        Duration::from_secs(5),
        app.oneshot(common::signed_relay_request(
            "AwMDAwMDAwMDAwMDAwMDAw",
            SECRET,
            NOW,
        )),
    )
    .await
    .expect("capacity must be released once the body completes")
    .unwrap();
    assert_eq!(
        third.status(),
        StatusCode::OK,
        "capacity must be reusable after the streaming body finishes"
    );
}

/// Dropping the response mid-stream must also return the permit.
///
/// A client that disconnects halfway through an SSE turn is routine. If the
/// permit only came back on clean completion, every abandoned turn would leak a
/// slot until the relay refused all traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoning_a_response_body_returns_the_permit() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let (_release, released) = oneshot::channel::<()>();
    let app = app_with(
        Arc::new(StreamingForwarder {
            admitted: admitted.clone(),
            release: Mutex::new(Some(released)),
        }),
        1,
    );

    let first = app
        .clone()
        .oneshot(common::signed_relay_request(
            "AQEBAQEBAQEBAQEBAQEBAQ",
            SECRET,
            NOW,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // Client goes away without reading the body.
    drop(first);

    let second = tokio::time::timeout(
        Duration::from_secs(5),
        app.oneshot(common::signed_relay_request(
            "AgICAgICAgICAgICAgICAg",
            SECRET,
            NOW,
        )),
    )
    .await
    .expect("an abandoned turn must not hold its slot forever")
    .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "dropping an unfinished response must release its admission permit"
    );
}
