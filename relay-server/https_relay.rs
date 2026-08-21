use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;

use crate::relay_auth::{AuthError, AuthGate, RelayAuthRequest};
use crate::relay_protocol::{
    base64url_decode, canonicalize_headers, sha256_base64url, RelaySigningInput,
};

/// Default cap on requests in flight.
///
/// Nothing else bounds this. Each in-flight request holds a task, a connection
/// slot, and up to `max_response_bytes` of streaming buffer, and the egress
/// deadlines are deliberately generous for SSE turns -- so a burst of slow
/// upstreams grows until the process runs out of memory or file descriptors.
/// That failure is an unattributable crash; refusing at the door is a documented
/// `503 relay_busy` the Worker already knows how to map.
pub const DEFAULT_MAX_CONCURRENCY: usize = 64;

/// Default ceiling on an accepted request body.
///
/// Enforced before authentication: computing an HMAC over an oversized body is
/// work an unauthenticated caller could otherwise force the relay to do.
pub const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_CANONICAL_HEADERS_BYTES: usize = 32 * 1024;
const CONTROL_PREFIX: &str = "x-codex-relay-";

/// Headers that must never appear in a canonical header block.
///
/// Two distinct reasons, kept in one list because the enforcement point is the
/// same:
///
/// * hop-by-hop and framing headers belong to the Worker->relay and
///   relay->upstream connections individually; reinjecting a caller-supplied
///   value would corrupt framing or leak proxy credentials.
/// * platform source-revealing headers describe the *original* client. The
///   relay exists so upstream sees only the VPS, so these must be refused even
///   when correctly signed -- the caller holding a signing key is not
///   authorization to attribute traffic to an arbitrary origin IP. The Worker
///   strips them on its side, but the relay is independently deployable and
///   cannot delegate this invariant to its caller.
///
/// Kept sorted so `x-codex-relay-*` (handled by CONTROL_PREFIX) is the only
/// pattern rule and everything else is an exact match.
const FORBIDDEN_HEADERS: &[&str] = &[
    "cdn-loop",
    "cf-connecting-ip",
    "cf-connecting-ipv6",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "cf-worker",
    "connection",
    "content-length",
    "forwarded",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "true-client-ip",
    "upgrade",
    "x-client-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    InvalidTarget,
    InvalidHeader,
    Timeout,
    Upstream,
    Unavailable,
}

pub struct ForwardRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<[String; 2]>,
    pub body: Bytes,
}

/// Upstream response body, still on the wire.
///
/// The relay must not buffer this: SSE turns from the Responses API stay open
/// for minutes, so a `Bytes` here would hold every event until the turn ended
/// and would let one caller pin an unbounded amount of relay memory.
pub type ForwardStream = BoxStream<'static, Result<Bytes, std::io::Error>>;

pub struct ForwardResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: ForwardStream,
}

impl ForwardResponse {
    /// Build a response whose body is already in memory. Only for callers that
    /// genuinely have complete bytes (tests, synthesized bodies).
    pub fn from_bytes(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body: Box::pin(futures_util::stream::once(async move { Ok(body) })),
        }
    }
}

pub trait Forwarder: Send + Sync + 'static {
    fn forward(
        &self,
        request: ForwardRequest,
    ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>>;
}

/// Response control headers (spec section 8).
///
/// These carry error *attribution* out of band: the status code alone is
/// ambiguous, because the relay's own 401/409/413 are indistinguishable from an
/// upstream that rejected the request, and a real upstream 502 is
/// indistinguishable from a relay that could not reach it. Without attribution
/// the Worker must guess, and guessing wrong either leaks the relay's auth
/// verdict to the client or masks a genuine upstream failure.
const RESULT_HEADER: &str = "x-codex-relay-result";
const ERROR_HEADER: &str = "x-codex-relay-error";
const REQUEST_ID_HEADER: &str = "x-codex-relay-request-id";
const RESULT_UPSTREAM: &str = "upstream";
const RESULT_ERROR: &str = "error";

/// Correlation id for one relay response.
///
/// Opaque and non-sequential: it exists to join a Worker log line to a relay log
/// line, so it must not double as a request counter that reveals traffic volume.
/// Reuses the `uuid` v4 CSPRNG already vendored for identity synthesis rather
/// than adding a second source of randomness.
fn new_request_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Stamp attribution onto an outgoing response.
///
/// Applied at the two -- and only two -- points where this relay produces a
/// response, so attribution cannot be forgotten on a new error branch: every
/// relay-side failure funnels through `Rejection`, and every forwarded reply
/// through `ForwardResponse`.
fn stamp_control_headers(response: &mut Response, result: &str, error_type: Option<&str>) {
    let headers = response.headers_mut();

    // Remove first, unconditionally. An upstream that sets `x-codex-relay-result:
    // upstream` on its own reply would otherwise forge attribution and convince
    // the Worker to pass a relay-shaped error through verbatim. The relay is the
    // only party entitled to speak in this namespace.
    headers.remove(RESULT_HEADER);
    headers.remove(ERROR_HEADER);
    headers.remove(REQUEST_ID_HEADER);

    headers.insert(
        HeaderName::from_static(RESULT_HEADER),
        HeaderValue::from_static(if result == RESULT_UPSTREAM {
            RESULT_UPSTREAM
        } else {
            RESULT_ERROR
        }),
    );
    if let Some(error_type) = error_type {
        // Machine codes are internal `&'static str` constants, never caller input.
        if let Ok(value) = HeaderValue::from_str(error_type) {
            headers.insert(HeaderName::from_static(ERROR_HEADER), value);
        }
    }
    if let Ok(value) = HeaderValue::from_str(&new_request_id()) {
        headers.insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
}

#[derive(Debug, Clone, Copy)]
struct Rejection {
    status: StatusCode,
    error_type: &'static str,
}

#[derive(Clone)]
pub struct RelayState {
    auth: Arc<Mutex<AuthGate>>,
    forwarder: Arc<dyn Forwarder>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    max_body_bytes: usize,
    /// Admission control. A permit is held for the whole request, including the
    /// streamed response body, so the cap reflects concurrent *upstream* work
    /// rather than just header parsing.
    admission: Arc<Semaphore>,
}

impl RelayState {
    pub fn new(auth: AuthGate, forwarder: Arc<dyn Forwarder>) -> Self {
        Self {
            auth: Arc::new(Mutex::new(auth)),
            forwarder,
            now: Arc::new(current_unix_seconds),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            admission: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENCY)),
        }
    }

    /// Override the in-flight request cap.
    #[must_use]
    pub fn with_max_concurrency(mut self, max_concurrency: usize) -> Self {
        self.admission = Arc::new(Semaphore::new(max_concurrency));
        self
    }

    /// Override the request-body ceiling.
    ///
    /// Separated from the constructors so the deployment contract can be
    /// tightened or loosened without a rebuild.
    #[must_use]
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_clock(
        auth: AuthGate,
        forwarder: Arc<dyn Forwarder>,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            auth: Arc::new(Mutex::new(auth)),
            forwarder,
            now,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            admission: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENCY)),
        }
    }
}

pub fn build_app(state: RelayState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/forward", post(forward))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

async fn forward(State(state): State<RelayState>, request: Request) -> Response {
    // Refuse rather than queue: an unbounded wait here would just move the
    // exhaustion from memory to latency, and the caller's own deadline would
    // expire without ever learning the relay was saturated.
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return reject(StatusCode::SERVICE_UNAVAILABLE, "relay_busy").into_response();
    };

    let (parts, body) = request.into_parts();
    let max_body_bytes = state.max_body_bytes;
    let body = match to_bytes(body, max_body_bytes.saturating_add(1)).await {
        Ok(body) if body.len() <= max_body_bytes => body,
        Ok(_) | Err(_) => {
            return reject(StatusCode::PAYLOAD_TOO_LARGE, "relay_body_too_large").into_response()
        }
    };

    let parsed = match ParsedRequest::from_headers(&parts.headers, body) {
        Ok(parsed) => parsed,
        Err(rejection) => return rejection.into_response(),
    };

    let auth_result = {
        let mut auth = match state.auth.lock() {
            Ok(auth) => auth,
            Err(_) => {
                return reject(StatusCode::INTERNAL_SERVER_ERROR, "relay_internal_error")
                    .into_response()
            }
        };
        auth.authenticate((state.now)(), parsed.auth_request())
    };

    if let Err(error) = auth_result {
        return auth_rejection(error).into_response();
    }

    let forward_request = parsed.into_forward_request();
    let result = state.forwarder.forward(forward_request).await;
    match result {
        Ok(response) => response.into_response(),
        Err(ForwardError::InvalidTarget) => {
            reject(StatusCode::BAD_REQUEST, "relay_invalid_target").into_response()
        }
        Err(ForwardError::InvalidHeader) => {
            reject(StatusCode::BAD_REQUEST, "relay_invalid_header").into_response()
        }
        Err(ForwardError::Timeout) => {
            reject(StatusCode::GATEWAY_TIMEOUT, "relay_upstream_timeout").into_response()
        }
        Err(ForwardError::Upstream) => {
            reject(StatusCode::BAD_GATEWAY, "relay_upstream_error").into_response()
        }
        Err(ForwardError::Unavailable) => {
            reject(StatusCode::BAD_GATEWAY, "relay_forward_unavailable").into_response()
        }
    }
}

fn auth_rejection(error: AuthError) -> Rejection {
    match error {
        AuthError::Protocol(_) => reject(StatusCode::BAD_REQUEST, "relay_protocol_error"),
        AuthError::Replay => reject(StatusCode::CONFLICT, "relay_replay"),
        AuthError::TimestampOutsideWindow | AuthError::UnknownKey | AuthError::InvalidSignature => {
            reject(StatusCode::UNAUTHORIZED, "relay_auth_error")
        }
    }
}

fn reject(status: StatusCode, error_type: &'static str) -> Rejection {
    Rejection { status, error_type }
}

struct ParsedRequest {
    version: u8,
    key_id: String,
    timestamp: i64,
    nonce: String,
    method: String,
    target: String,
    headers: Vec<[String; 2]>,
    body: Bytes,
    signature: String,
}

impl ParsedRequest {
    fn from_headers(headers: &HeaderMap, body: Bytes) -> Result<Self, Rejection> {
        let version = single_header(headers, "x-codex-relay-version")?
            .parse::<u8>()
            .map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
        let key_id = single_header(headers, "x-codex-relay-key-id")?.to_owned();
        let timestamp = single_header(headers, "x-codex-relay-timestamp")?
            .parse::<i64>()
            .map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
        let nonce = single_header(headers, "x-codex-relay-nonce")?.to_owned();
        let method = single_header(headers, "x-codex-relay-method")?.to_owned();
        let target = decode_utf8_header(headers, "x-codex-relay-target")?;
        let body_sha256 = single_header(headers, "x-codex-relay-body-sha256")?;
        if body_sha256 != sha256_base64url(&body) {
            return Err(reject(
                StatusCode::BAD_REQUEST,
                "relay_body_digest_mismatch",
            ));
        }
        let header_block = decode_header_block(headers)?;
        let signature = single_header(headers, "x-codex-relay-signature")?.to_owned();

        Ok(Self {
            version,
            key_id,
            timestamp,
            nonce,
            method,
            target,
            headers: header_block,
            body,
            signature,
        })
    }

    fn auth_request(&self) -> RelayAuthRequest<'_> {
        RelayAuthRequest {
            signing: RelaySigningInput {
                version: self.version,
                key_id: &self.key_id,
                timestamp: self.timestamp,
                nonce: &self.nonce,
                method: &self.method,
                target: &self.target,
                headers: &self.headers,
                body: &self.body,
            },
            signature: &self.signature,
        }
    }

    fn into_forward_request(self) -> ForwardRequest {
        ForwardRequest {
            method: self.method,
            target: self.target,
            headers: self.headers,
            body: self.body,
        }
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, Rejection> {
    let name = HeaderName::from_static(name);
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
    if values.next().is_some() {
        return Err(reject(StatusCode::BAD_REQUEST, "relay_duplicate_control"));
    }
    value
        .to_str()
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))
}

fn decode_utf8_header(headers: &HeaderMap, name: &'static str) -> Result<String, Rejection> {
    let encoded = single_header(headers, name)?;
    let decoded = base64url_decode(encoded)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
    String::from_utf8(decoded).map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))
}

fn decode_header_block(headers: &HeaderMap) -> Result<Vec<[String; 2]>, Rejection> {
    let encoded = single_header(headers, "x-codex-relay-headers")?;
    let decoded = base64url_decode(encoded)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
    if decoded.len() > MAX_CANONICAL_HEADERS_BYTES {
        return Err(reject(StatusCode::BAD_REQUEST, "relay_headers_too_large"));
    }
    let block = String::from_utf8(decoded)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
    if !block.is_empty() && !block.ends_with('\n') {
        return Err(reject(StatusCode::BAD_REQUEST, "relay_protocol_error"));
    }
    if block.is_empty() {
        return Ok(Vec::new());
    }

    let mut parsed = Vec::new();
    for line in block.strip_suffix('\n').unwrap_or(&block).split('\n') {
        if line.is_empty() {
            return Err(reject(StatusCode::BAD_REQUEST, "relay_protocol_error"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
        if FORBIDDEN_HEADERS.contains(&name) || name.starts_with(CONTROL_PREFIX) {
            return Err(reject(StatusCode::BAD_REQUEST, "relay_forbidden_header"));
        }
        parsed.push([name.to_owned(), value.to_owned()]);
    }

    let canonical = canonicalize_headers(&parsed)
        .map_err(|_| reject(StatusCode::BAD_REQUEST, "relay_protocol_error"))?;
    if canonical != block {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "relay_noncanonical_headers",
        ));
    }
    Ok(parsed)
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

impl IntoResponse for ForwardResponse {
    fn into_response(self) -> Response {
        let mut response = Response::new(Body::from_stream(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        // Marked `upstream` even for an upstream 4xx/5xx: the status belongs to
        // the upstream and the Worker must return it verbatim rather than
        // rewriting it into a relay error.
        stamp_control_headers(&mut response, RESULT_UPSTREAM, None);
        response
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {
                "type": self.error_type,
                "message": "relay request rejected"
            }
        });
        let mut response = axum::Json(body).into_response();
        *response.status_mut() = self.status;
        stamp_control_headers(&mut response, RESULT_ERROR, Some(self.error_type));
        response
    }
}
