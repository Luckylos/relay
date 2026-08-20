use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{HeaderMap, Request, StatusCode},
};
use codex_egress_relay::{
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
    let method = "POST";
    let target = "https://api.example.com/v1/responses";
    let nonce = "AgICAgICAgICAgICAgICAg";
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
            codex_egress_relay::relay_protocol::sha256_base64url(&body),
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
            codex_egress_relay::relay_protocol::sha256_base64url(&body),
        )
        .header(
            "x-codex-relay-headers",
            base64url_encode(header_block.as_bytes()),
        )
        .header("x-codex-relay-signature", signature)
        .body(Body::from(body))
        .unwrap()
}

fn app_with(calls: Arc<AtomicUsize>) -> axum::Router {
    let mut keys = KeyRing::default();
    keys.insert("current", SECRET);
    let auth = AuthGate::new(keys, AuthPolicy::new(300));
    let forwarder = Arc::new(RecordingForwarder { calls });
    let clock = Arc::new(|| NOW);
    build_app(RelayState::with_clock(auth, forwarder, clock))
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
