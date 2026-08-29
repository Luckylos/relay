use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{HeaderMap, Request, StatusCode},
};
use egress_relay::{
    https_relay::{
        build_app, ForwardError, ForwardRequest, ForwardResponse, Forwarder, RelayState,
    },
    relay_auth::{AuthGate, AuthPolicy, KeyRing},
    relay_protocol::{
        base64url_encode, canonicalize_headers, sign_relay_request, RelaySigningInput,
    },
};
use futures_util::future::BoxFuture;
use tower::ServiceExt;

const NOW: i64 = 1_700_000_000;
const SECRET: &[u8] = b"entrypoint-fixture-secret";

struct RecordingForwarder {
    calls: Arc<AtomicUsize>,
}

impl Forwarder for RecordingForwarder {
    fn forward(
        &self,
        request: ForwardRequest,
    ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            assert_eq!(request.method, "POST");
            assert_eq!(request.target, "https://api.example.com/v1/responses");
            Ok(ForwardResponse::from_bytes(
                StatusCode::ACCEPTED,
                HeaderMap::new(),
                Bytes::from_static(b"forwarded"),
            ))
        })
    }
}

fn signed_request() -> Request<Body> {
    signed_request_with_nonce("AgICAgICAgICAgICAgICAg")
}

/// Same validly signed request, with a caller-chosen nonce.
///
/// Concurrency tests need several requests in flight at once; reusing one nonce
/// would make the replay gate reject them, hiding whatever the concurrency gate
/// does.
fn signed_request_with_nonce(nonce: &str) -> Request<Body> {
    let method = "POST";
    let target = "https://api.example.com/v1/responses";
    let headers = vec![["content-type".to_owned(), "application/json".to_owned()]];
    let body = br#"{"model":"fixture"}"#.to_vec();
    let input = RelaySigningInput {
        version: 1,
        key_id: "current",
        timestamp: NOW,
        nonce,
        method,
        target,
        headers: &headers,
        body: &body,
    };
    let signature = sign_relay_request(&input, SECRET).unwrap();
    let header_block = canonicalize_headers(&headers).unwrap();

    Request::builder()
        .method("POST")
        .uri("/v1/forward")
        .header("content-type", "application/octet-stream")
        .header("x-codex-relay-version", "1")
        .header("x-codex-relay-key-id", "current")
        .header("x-codex-relay-timestamp", NOW.to_string())
        .header("x-codex-relay-nonce", nonce)
        .header("x-codex-relay-method", method)
        .header("x-codex-relay-target", base64url_encode(target.as_bytes()))
        .header(
            "x-codex-relay-body-sha256",
            egress_relay::relay_protocol::sha256_base64url(&body),
        )
        .header(
            "x-codex-relay-headers",
            base64url_encode(header_block.as_bytes()),
        )
        .header("x-codex-relay-signature", signature)
        .body(Body::from(body))
        .unwrap()
}

fn empty_header_request() -> Request<Body> {
    let method = "POST";
    let target = "https://api.example.com/v1/responses";
    let nonce = "AwMDAwMDAwMDAwMDAwMDAw";
    let headers: Vec<[String; 2]> = Vec::new();
    let body = br#"{\"model\":\"fixture\"}"#.to_vec();
    let input = RelaySigningInput {
        version: 1,
        key_id: "current",
        timestamp: NOW,
        nonce,
        method,
        target,
        headers: &headers,
        body: &body,
    };
    let signature = sign_relay_request(&input, SECRET).unwrap();
    let header_block = canonicalize_headers(&headers).unwrap();

    Request::builder()
        .method("POST")
        .uri("/v1/forward")
        .header("x-codex-relay-version", "1")
        .header("x-codex-relay-key-id", "current")
        .header("x-codex-relay-timestamp", NOW.to_string())
        .header("x-codex-relay-nonce", nonce)
        .header("x-codex-relay-method", method)
        .header("x-codex-relay-target", base64url_encode(target.as_bytes()))
        .header(
            "x-codex-relay-body-sha256",
            egress_relay::relay_protocol::sha256_base64url(&body),
        )
        .header(
            "x-codex-relay-headers",
            base64url_encode(header_block.as_bytes()),
        )
        .header("x-codex-relay-signature", signature)
        .body(Body::from(body))
        .unwrap()
}

/// Relay-generated errors must be attributable as such, and must not be
/// confusable with a genuine upstream status of the same number.
///
/// Without a machine-readable marker the Worker can only guess from the status
/// code, which is ambiguous in both directions: the relay's own 401/409/413 look
/// like upstream rejections, and a real upstream 502 looks like a relay failure.
/// Spec section 8 resolves this with `X-Codex-Relay-Result`.
#[tokio::test]
async fn relay_generated_errors_are_marked_as_relay_errors() {
    // One case per class of relay-side failure, each reached by a different
    // code path so the marker cannot be bolted onto a single branch.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut bad_sig = signed_request();
    *bad_sig
        .headers_mut()
        .get_mut("x-codex-relay-signature")
        .unwrap() = axum::http::HeaderValue::from_static("invalid");

    let auth_error = app_with(calls.clone()).oneshot(bad_sig).await.unwrap();

    assert_eq!(auth_error.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        auth_error
            .headers()
            .get("x-codex-relay-result")
            .and_then(|v| v.to_str().ok()),
        Some("error"),
        "an auth failure is the relay's own verdict, not the upstream's"
    );
    assert_eq!(
        auth_error
            .headers()
            .get("x-codex-relay-error")
            .and_then(|v| v.to_str().ok()),
        Some("relay_auth_error"),
        "the machine code must travel in the header, not only in the JSON body"
    );
    assert!(
        auth_error
            .headers()
            .get("x-codex-relay-request-id")
            .is_some(),
        "every relay response carries a correlation id"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // A replay is a distinct machine code on a distinct status.
    let app = app_with(calls.clone());
    let _first = app.clone().oneshot(signed_request()).await.unwrap();
    let replay = app.oneshot(signed_request()).await.unwrap();

    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(
        replay
            .headers()
            .get("x-codex-relay-result")
            .and_then(|v| v.to_str().ok()),
        Some("error")
    );
    assert_eq!(
        replay
            .headers()
            .get("x-codex-relay-error")
            .and_then(|v| v.to_str().ok()),
        Some("relay_replay")
    );
}

/// A genuine upstream response -- including an upstream 4xx/5xx -- must be
/// marked `upstream` so the Worker returns it verbatim instead of masking it
/// behind a relay error.
#[tokio::test]
async fn upstream_responses_are_marked_as_upstream() {
    let calls = Arc::new(AtomicUsize::new(0));
    let response = app_with(calls.clone())
        .oneshot(signed_request())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response
            .headers()
            .get("x-codex-relay-result")
            .and_then(|v| v.to_str().ok()),
        Some("upstream"),
        "a forwarded response belongs to the upstream"
    );
    assert!(
        response.headers().get("x-codex-relay-error").is_none(),
        "there is no error code when nothing failed"
    );
    assert!(
        response.headers().get("x-codex-relay-request-id").is_some(),
        "correlation id is present on success too"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// An upstream must not be able to forge its own attribution.
///
/// If upstream-supplied `x-codex-relay-*` headers survived, an upstream (or
/// anything able to influence its response headers) could stamp
/// `result: upstream` onto a reply, or overwrite the request id to poison
/// correlation. The relay owns this namespace, so it overwrites rather than
/// merges -- and the test proves the *upstream's* value is gone, not merely that
/// some value is present.
#[tokio::test]
async fn upstream_supplied_control_headers_are_overwritten_not_merged() {
    struct ForgingForwarder;

    impl Forwarder for ForgingForwarder {
        fn forward(
            &self,
            _request: ForwardRequest,
        ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>> {
            Box::pin(async move {
                let mut headers = HeaderMap::new();
                headers.insert("x-codex-relay-result", "error".parse().unwrap());
                headers.insert("x-codex-relay-error", "relay_auth_error".parse().unwrap());
                headers.insert(
                    "x-codex-relay-request-id",
                    "forged-by-upstream".parse().unwrap(),
                );
                Ok(ForwardResponse::from_bytes(
                    StatusCode::OK,
                    headers,
                    Bytes::from_static(b"upstream body"),
                ))
            })
        }
    }

    let mut keys = KeyRing::default();
    keys.insert("current", SECRET);
    let app = build_app(RelayState::with_clock(
        AuthGate::new(keys, AuthPolicy::new(300)),
        Arc::new(ForgingForwarder),
        Arc::new(|| NOW),
    ));

    let response = app.oneshot(signed_request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-codex-relay-result")
            .and_then(|v| v.to_str().ok()),
        Some("upstream"),
        "the relay's own verdict must win over the upstream's forged one"
    );
    assert!(
        response.headers().get("x-codex-relay-error").is_none(),
        "a forged error code must not survive on a successful forward"
    );
    assert_ne!(
        response
            .headers()
            .get("x-codex-relay-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("forged-by-upstream"),
        "the request id must be minted by the relay, never accepted from upstream"
    );
    // Exactly one value each: `insert` must have replaced, not appended.
    assert_eq!(
        response
            .headers()
            .get_all("x-codex-relay-result")
            .iter()
            .count(),
        1
    );
    assert_eq!(
        response
            .headers()
            .get_all("x-codex-relay-request-id")
            .iter()
            .count(),
        1
    );
}

/// The request-body ceiling must be operator-configurable, and must be enforced
/// before the request is trusted enough to authenticate.
///
/// A hardcoded ceiling means the deployment contract cannot be tightened for a
/// relay that fronts small requests, nor loosened for one that legitimately
/// carries large ones -- the only lever is a rebuild. Enforcing it *before*
/// signature verification also matters: HMAC over an oversized body is work an
/// unauthenticated caller can force the relay to do.
#[tokio::test]
async fn the_request_body_ceiling_is_configurable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut keys = KeyRing::default();
    keys.insert("current", SECRET);
    let app = build_app(
        RelayState::with_clock(
            AuthGate::new(keys, AuthPolicy::new(300)),
            Arc::new(RecordingForwarder {
                calls: calls.clone(),
            }),
            Arc::new(|| NOW),
        )
        // Far below the 10 MiB default, so the rejection can only come from the
        // configured value being honoured.
        .with_max_body_bytes(8),
    );

    let response = app.oneshot(signed_request()).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a body over the configured ceiling must be rejected"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "an oversized body must never reach the forwarder"
    );
}

/// Concurrency saturation must be refused with `relay_busy`, not absorbed.
///
/// Nothing else in the relay bounds how many requests are in flight. Each one
/// holds a task, a connection slot, and up to `max_response_bytes` of streaming
/// buffer, and the deadlines are deliberately generous for SSE turns -- so a
/// burst of slow upstreams grows until the process is out of memory or file
/// descriptors, which fails as an unattributable crash instead of a documented
/// `503`. The Worker already maps `relay_busy` to a client-visible 503; this is
/// the missing producer of that code.
// A multi-threaded runtime: this test needs one request genuinely parked inside
// the forwarder while another is submitted. On the default single-threaded
// runtime that overlap depends on yield ordering, which makes the test flaky
// rather than wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturation_is_refused_as_relay_busy_rather_than_queued() {
    let admitted = Arc::new(AtomicUsize::new(0));
    let mut keys = KeyRing::default();
    keys.insert("current", SECRET);
    // A oneshot, not a `Notify`: it delivers even if the receiver has not begun
    // awaiting yet, so the test cannot deadlock on task-scheduling order under
    // the single-threaded test runtime.
    let (release, released) = tokio::sync::oneshot::channel::<()>();

    let app = build_app(
        RelayState::with_clock(
            AuthGate::new(keys, AuthPolicy::new(300)),
            // A forwarder that parks until released: this is the shape of a slow
            // upstream, which is what actually accumulates in production.
            Arc::new(BlockingForwarder {
                admitted: admitted.clone(),
                released: Mutex::new(Some(released)),
            }),
            Arc::new(|| NOW),
        )
        .with_max_concurrency(1),
    );

    // Hold the single slot with an in-flight request.
    let first = tokio::spawn({
        let app = app.clone();
        async move {
            app.oneshot(signed_request_with_nonce("AQEBAQEBAQEBAQEBAQEBAQ"))
                .await
                .unwrap()
        }
    });
    // Wait until it is genuinely inside the forwarder, so the second request
    // cannot pass merely because the first had not started yet.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while admitted.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the first request never reached the forwarder"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    // Bounded: an implementation that queues instead of refusing would park here
    // forever. Failing on the timeout keeps that regression a fast, readable
    // failure instead of a hung test run.
    let rejected = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        app.clone()
            .oneshot(signed_request_with_nonce("AgICAgICAgICAgICAgICAg")),
    )
    .await
    .expect("a saturated relay must answer immediately, not queue behind the in-flight request")
    .unwrap();

    assert_eq!(
        rejected.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a request beyond the concurrency limit must be refused, not queued"
    );
    assert_eq!(
        rejected
            .headers()
            .get("x-codex-relay-error")
            .and_then(|v| v.to_str().ok()),
        Some("relay_busy"),
        "the refusal must carry the machine code the Worker already maps to 503"
    );
    assert_eq!(
        admitted.load(Ordering::SeqCst),
        1,
        "the refused request must never reach the forwarder"
    );

    // The slot must be returned once the in-flight request finishes.
    release
        .send(())
        .expect("the parked forwarder must still be listening");
    assert_eq!(first.await.unwrap().status(), StatusCode::ACCEPTED);
    let after = app
        .oneshot(signed_request_with_nonce("AwMDAwMDAwMDAwMDAwMDAw"))
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::ACCEPTED,
        "capacity must be reusable: a permit leak would wedge the relay shut"
    );
}

/// A forwarder that reports admission then parks until released.
struct BlockingForwarder {
    admitted: Arc<AtomicUsize>,
    released: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl Forwarder for BlockingForwarder {
    fn forward(
        &self,
        _request: ForwardRequest,
    ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>> {
        self.admitted.fetch_add(1, Ordering::SeqCst);
        // Only the first admitted request parks. With a cap of 1 no second
        // request can reach here, so taking the receiver is not a race.
        let released = self.released.lock().unwrap().take();
        Box::pin(async move {
            if let Some(released) = released {
                released.await.expect("release channel dropped");
            }
            Ok(ForwardResponse::from_bytes(
                StatusCode::ACCEPTED,
                HeaderMap::new(),
                Bytes::from_static(b"forwarded"),
            ))
        })
    }
}

fn app_with(calls: Arc<AtomicUsize>) -> axum::Router {
    let mut keys = KeyRing::default();
    keys.insert("current", SECRET);
    let auth = AuthGate::new(keys, AuthPolicy::new(300));
    let forwarder = Arc::new(RecordingForwarder { calls });
    let clock = Arc::new(|| NOW);
    build_app(RelayState::with_clock(auth, forwarder, clock))
}

/// Build a validly signed request whose canonical header block carries `name`.
///
/// The signature is computed over the block that actually contains the header,
/// so a rejection can only come from the relay's own header policy -- never
/// from a signature or digest mismatch.
fn signed_request_with_header(name: &str, value: &str, nonce: &str) -> Request<Body> {
    let method = "POST";
    let target = "https://api.example.com/v1/responses";
    let headers = vec![
        ["content-type".to_owned(), "application/json".to_owned()],
        [name.to_owned(), value.to_owned()],
    ];
    let body = br#"{"model":"fixture"}"#.to_vec();
    let input = RelaySigningInput {
        version: 1,
        key_id: "current",
        timestamp: NOW,
        nonce,
        method,
        target,
        headers: &headers,
        body: &body,
    };
    let signature = sign_relay_request(&input, SECRET).unwrap();
    let header_block = canonicalize_headers(&headers).unwrap();

    Request::builder()
        .method("POST")
        .uri("/v1/forward")
        .header("content-type", "application/octet-stream")
        .header("x-codex-relay-version", "1")
        .header("x-codex-relay-key-id", "current")
        .header("x-codex-relay-timestamp", NOW.to_string())
        .header("x-codex-relay-nonce", nonce)
        .header("x-codex-relay-method", method)
        .header("x-codex-relay-target", base64url_encode(target.as_bytes()))
        .header(
            "x-codex-relay-body-sha256",
            egress_relay::relay_protocol::sha256_base64url(&body),
        )
        .header(
            "x-codex-relay-headers",
            base64url_encode(header_block.as_bytes()),
        )
        .header("x-codex-relay-signature", signature)
        .body(Body::from(body))
        .unwrap()
}

/// Platform source-revealing headers must not survive into the upstream request.
///
/// The whole point of the relay is that upstream sees the VPS and nothing about
/// the original client. The Worker strips these on its side, but the relay is an
/// independently deployable trust boundary reachable by anyone holding a signing
/// key, so it must enforce the rule itself rather than trusting its caller.
#[tokio::test]
async fn platform_source_revealing_headers_are_rejected_before_the_forwarder() {
    // Every header the Worker's own strip list treats as source-revealing.
    let source_revealing = [
        "cdn-loop",
        "cf-connecting-ip",
        "cf-connecting-ipv6",
        "cf-ipcountry",
        "cf-ray",
        "cf-visitor",
        "cf-worker",
        "forwarded",
        "true-client-ip",
        "x-client-ip",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
    ];

    for (index, name) in source_revealing.iter().enumerate() {
        let calls = Arc::new(AtomicUsize::new(0));
        // Distinct nonce per case so a rejection is never a replay artifact.
        let nonce = base64url_encode(&[index as u8 + 0x40; 16]);
        let response = app_with(calls.clone())
            .oneshot(signed_request_with_header(name, "203.0.113.7", &nonce))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "signed block carrying `{name}` must be rejected"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "`{name}` must be rejected before any egress"
        );
    }
}

/// The rejection above must be a targeted policy, not a blanket denial: the
/// business headers the spec explicitly binds into the signature still pass.
#[tokio::test]
async fn spec_permitted_business_headers_still_reach_the_forwarder() {
    for (index, (name, value)) in [
        ("authorization", "Bearer upstream-token"),
        ("accept", "text/event-stream"),
        ("accept-encoding", "gzip"),
        ("session-id", "abc123"),
        ("x-client-version", "1.2.3"),
    ]
    .iter()
    .enumerate()
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let nonce = base64url_encode(&[index as u8 + 0x70; 16]);
        let response = app_with(calls.clone())
            .oneshot(signed_request_with_header(name, value, &nonce))
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::ACCEPTED,
            "spec-permitted header `{name}` must be forwarded"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "`{name}` must reach egress"
        );
    }
}

#[tokio::test]
async fn valid_forward_request_enters_the_injected_forwarder() {
    let calls = Arc::new(AtomicUsize::new(0));
    let response = app_with(calls.clone())
        .oneshot(signed_request())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        b"forwarded"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn empty_business_header_block_is_valid() {
    let calls = Arc::new(AtomicUsize::new(0));
    let response = app_with(calls.clone())
        .oneshot(empty_header_request())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_signature_is_rejected_without_entering_the_forwarder() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut request = signed_request();
    *request
        .headers_mut()
        .get_mut("x-codex-relay-signature")
        .unwrap() = axum::http::HeaderValue::from_static("invalid");

    let response = app_with(calls.clone()).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn body_digest_mismatch_is_rejected_without_entering_the_forwarder() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut request = signed_request();
    *request
        .headers_mut()
        .get_mut("x-codex-relay-body-sha256")
        .unwrap() =
        axum::http::HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let response = app_with(calls.clone()).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn replayed_nonce_is_rejected_before_the_second_forward() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = app_with(calls.clone());

    let first = app.clone().oneshot(signed_request()).await.unwrap();
    let second = app.oneshot(signed_request()).await.unwrap();

    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn only_the_fixed_forward_route_accepts_post_and_health_is_generic() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = app_with(calls.clone());

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let unknown = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/not-forward")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let wrong_method = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/forward")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(health.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        br#"{"status":"ok"}"#
    );
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Build a validly signed v2 envelope: new control namespace, v2 signature.
///
/// Deliberately a separate builder rather than a parameter on the v1 one. The
/// two generations must be constructible independently, so a change that
/// accidentally couples them (a shared prefix constant, a shared version field)
/// fails here instead of silently testing one generation twice.
fn signed_request_v2(nonce: &str) -> Request<Body> {
    let method = "POST";
    let target = "https://api.example.com/v1/responses";
    let headers = vec![["content-type".to_owned(), "application/json".to_owned()]];
    let body = br#"{"model":"fixture"}"#.to_vec();
    let input = RelaySigningInput {
        version: 2,
        key_id: "current",
        timestamp: NOW,
        nonce,
        method,
        target,
        headers: &headers,
        body: &body,
    };
    let signature = sign_relay_request(&input, SECRET).unwrap();
    let header_block = canonicalize_headers(&headers).unwrap();

    Request::builder()
        .method("POST")
        .uri("/v1/forward")
        .header("content-type", "application/octet-stream")
        .header("x-egress-relay-version", "2")
        .header("x-egress-relay-key-id", "current")
        .header("x-egress-relay-timestamp", NOW.to_string())
        .header("x-egress-relay-nonce", nonce)
        .header("x-egress-relay-method", method)
        .header("x-egress-relay-target", base64url_encode(target.as_bytes()))
        .header(
            "x-egress-relay-body-sha256",
            egress_relay::relay_protocol::sha256_base64url(&body),
        )
        .header(
            "x-egress-relay-headers",
            base64url_encode(header_block.as_bytes()),
        )
        .header("x-egress-relay-signature", signature)
        .body(Body::from(body))
        .unwrap()
}

/// Both control namespaces are accepted on the way in.
///
/// This is the property that lets the relay ship before the ingresses: it runs
/// in front of a Worker still speaking the old namespace and a Worker already
/// speaking the new one, without a coordinated restart. Asserting both in one
/// test keeps a regression from passing because only the generation under
/// active development still works.
#[tokio::test]
async fn both_control_generations_are_accepted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = app_with(calls.clone());

    let legacy = app.clone().oneshot(signed_request()).await.unwrap();
    let current = app
        .oneshot(signed_request_v2("AQEBAQEBAQEBAQEBAQEBAQ"))
        .await
        .unwrap();

    assert_eq!(legacy.status(), StatusCode::ACCEPTED);
    assert_eq!(current.status(), StatusCode::ACCEPTED);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "both generations reach the forwarder, so neither is being rejected early"
    );
}

/// Every reply is attributed in both namespaces, with the same values.
///
/// An ingress that has not been redeployed reads only the old names. If the
/// relay answered a legacy request in the new namespace only -- or answered in
/// whichever namespace the request happened to use -- that ingress would see an
/// unattributed reply and fail closed to `502 relay_unavailable`, turning a
/// working upstream call into an outage that looks like a relay fault.
#[tokio::test]
async fn attribution_is_emitted_in_both_namespaces() {
    let calls = Arc::new(AtomicUsize::new(0));
    let app = app_with(calls.clone());

    // Success path, and the v2 envelope specifically: the legacy names must be
    // present even when nothing in the request used them.
    let ok = app
        .clone()
        .oneshot(signed_request_v2("AQEBAQEBAQEBAQEBAQEBAQ"))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::ACCEPTED);
    for name in ["x-egress-relay-result", "x-codex-relay-result"] {
        assert_eq!(
            ok.headers().get(name).and_then(|v| v.to_str().ok()),
            Some("upstream"),
            "{name} must mark a forwarded reply as upstream"
        );
    }
    let ids: Vec<&str> = ["x-egress-relay-request-id", "x-codex-relay-request-id"]
        .iter()
        .map(|name| {
            ok.headers()
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_else(|| panic!("{name} missing"))
        })
        .collect();
    assert_eq!(
        ids[0], ids[1],
        "one id per response: a Worker log line must join to the same relay log \
         line whichever name it read"
    );

    // Error path, reached with a legacy envelope: the new names must be present
    // even when nothing in the request used them.
    let mut bad_sig = signed_request();
    *bad_sig
        .headers_mut()
        .get_mut("x-codex-relay-signature")
        .unwrap() = axum::http::HeaderValue::from_static("invalid");
    let rejected = app.oneshot(bad_sig).await.unwrap();

    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    for name in ["x-egress-relay-result", "x-codex-relay-result"] {
        assert_eq!(
            rejected.headers().get(name).and_then(|v| v.to_str().ok()),
            Some("error"),
            "{name} must mark the relay's own verdict"
        );
    }
    for name in ["x-egress-relay-error", "x-codex-relay-error"] {
        assert_eq!(
            rejected.headers().get(name).and_then(|v| v.to_str().ok()),
            Some("relay_auth_error"),
            "{name} must carry the machine code"
        );
    }
}

/// One envelope may not draw fields from both namespaces.
///
/// Resolving a mix -- by preferring one namespace, or by falling back per field
/// -- would let a caller present two different envelopes and leave the relay to
/// choose which one it authenticates. The fields are exactly what the signature
/// covers, so the choice is security-relevant and is refused instead.
#[tokio::test]
async fn a_request_mixing_both_namespaces_is_refused() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut mixed = signed_request_v2("AQEBAQEBAQEBAQEBAQEBAQ");
    mixed.headers_mut().insert(
        "x-codex-relay-key-id",
        axum::http::HeaderValue::from_static("current"),
    );

    let response = app_with(calls.clone()).oneshot(mixed).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("x-egress-relay-error")
            .and_then(|v| v.to_str().ok()),
        Some("relay_duplicate_control")
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "refused before the forwarder, so the ambiguous envelope never egresses"
    );
}

/// Neither control namespace may appear inside the signed business header block.
///
/// Holding a signing key is not permission to inject relay control fields. A
/// legacy-named control header in the block is the sharper case: it would reach
/// an upstream, and on the response path an ingress still reading the old names
/// treats it as the relay's own attribution. Both prefixes stay refused for as
/// long as any live ingress reads either.
#[tokio::test]
async fn control_headers_in_the_signed_block_are_refused_in_both_namespaces() {
    for (index, name) in [
        "x-codex-relay-result",
        "x-codex-relay-target",
        "x-egress-relay-result",
        "x-egress-relay-target",
    ]
    .iter()
    .enumerate()
    {
        let calls = Arc::new(AtomicUsize::new(0));
        // Distinct nonce per case: a replay rejection would also be a 4xx and
        // would hide whether the header policy fired at all.
        let nonce = format!("A{}EBAQEBAQEBAQEBAQEBAQ", index);
        let request = signed_request_with_header(name, "forged", &nonce);

        let response = app_with(calls.clone()).oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{name} must be refused inside the signed block"
        );
        assert_eq!(
            response
                .headers()
                .get("x-egress-relay-error")
                .and_then(|v| v.to_str().ok()),
            Some("relay_forbidden_header"),
            "{name} must be refused as a forbidden header, not some other fault"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "{name} must never reach the forwarder"
        );
    }
}

/// An upstream cannot forge attribution in either namespace.
///
/// The existing coverage proves this for the legacy names. Adding the new
/// namespace matters more than it looks: the relay now *emits* both, so a
/// scrub that removed only the generation it was about to write would leave the
/// upstream's value in the other one, and an ingress reading that name would
/// trust it.
#[tokio::test]
async fn upstream_cannot_forge_attribution_in_the_new_namespace() {
    struct ForgingForwarder;

    impl Forwarder for ForgingForwarder {
        fn forward(
            &self,
            _request: ForwardRequest,
        ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>> {
            Box::pin(async move {
                let mut headers = HeaderMap::new();
                headers.insert("x-egress-relay-result", "error".parse().unwrap());
                headers.insert("x-egress-relay-error", "relay_auth_error".parse().unwrap());
                headers.insert(
                    "x-egress-relay-request-id",
                    "forged-by-upstream".parse().unwrap(),
                );
                Ok(ForwardResponse::from_bytes(
                    StatusCode::OK,
                    headers,
                    Bytes::from_static(b"forwarded"),
                ))
            })
        }
    }

    let mut keys = KeyRing::default();
    keys.insert("current", SECRET);
    let auth = AuthGate::new(keys, AuthPolicy::new(300));
    let clock = Arc::new(|| NOW);
    let app = build_app(RelayState::with_clock(
        auth,
        Arc::new(ForgingForwarder),
        clock,
    ));

    let response = app.oneshot(signed_request()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-egress-relay-result")
            .and_then(|v| v.to_str().ok()),
        Some("upstream"),
        "the relay's verdict replaces the upstream's claim"
    );
    assert!(
        response.headers().get("x-egress-relay-error").is_none(),
        "the upstream's forged error code must be gone, not merely overwritten \
         with another error"
    );
    assert_ne!(
        response
            .headers()
            .get("x-egress-relay-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("forged-by-upstream"),
        "correlation ids must come from the relay so they cannot be poisoned"
    );
}
