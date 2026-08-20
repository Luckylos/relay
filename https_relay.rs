use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::future::BoxFuture;

use crate::relay_auth::{AuthError, AuthGate, RelayAuthRequest};
use crate::relay_protocol::{
    base64url_decode, canonicalize_headers, sha256_base64url, RelaySigningInput,
};

const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_CANONICAL_HEADERS_BYTES: usize = 32 * 1024;
const CONTROL_PREFIX: &str = "x-codex-relay-";
const FORWARD_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    Unavailable,
}

pub struct ForwardRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<[String; 2]>,
    pub body: Bytes,
}

pub struct ForwardResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub trait Forwarder: Send + Sync + 'static {
    fn forward(
        &self,
        request: ForwardRequest,
    ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>>;
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
}

impl RelayState {
    pub fn new(auth: AuthGate, forwarder: Arc<dyn Forwarder>) -> Self {
        Self {
            auth: Arc::new(Mutex::new(auth)),
            forwarder,
            now: Arc::new(current_unix_seconds),
        }
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
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_BODY_BYTES + 1).await {
        Ok(body) if body.len() <= MAX_BODY_BYTES => body,
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
        if FORWARD_HEADERS.contains(&name) || name.starts_with(CONTROL_PREFIX) {
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
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
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
        response
    }
}
