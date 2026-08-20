//! Dynamic HTTPS forwarding for the relay.
//!
//! This is the only component in the crate that opens connections to
//! caller-supplied hostnames, so it is where the frozen egress contract is
//! enforced end to end:
//!
//! * the target is re-validated with [`Target::parse`] before any network
//!   access — HTTPS only, no explicit port, no userinfo/fragment/IP literal;
//! * DNS answers pass through [`SafeResolver`], so private/loopback/link-local
//!   results are rejected before `connect()` rather than after;
//! * redirects are never followed, because hop 2 would escape both the target
//!   policy and the resolver;
//! * the TLS stack is the shared, fingerprint-critical rustls + aws-lc-rs
//!   config from [`crate::tls`], never reqwest's default provider;
//! * no proxy env var can divert egress (`.no_proxy()` via the resolver seam).
//!
//! Upstream errors are collapsed into coarse [`ForwardError`] variants so that
//! hostnames, DNS answers and TLS details never reach the client.

use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt;
use reqwest::dns::Resolve;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, Method};

use crate::https_relay::{ForwardError, ForwardRequest, ForwardResponse, Forwarder};
use crate::relay_target::Target;

/// Default ceiling for a whole upstream request/response exchange.
pub const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// Default deadline for the upstream's response *headers*.
///
/// This must be separate from — and far shorter than — the overall ceiling. The
/// overall ceiling has to stay long because SSE turns legitimately run for
/// minutes; without a header deadline, an upstream that completes the handshake
/// and then says nothing would hold a relay connection for that entire window.
pub const DEFAULT_RESPONSE_HEADER_TIMEOUT_SECS: u64 = 30;

/// Default ceiling on a single relayed response body.
///
/// Streaming removes the natural memory bound that buffering provided, so an
/// explicit ceiling is what stops one upstream from relaying unbounded bytes
/// through the relay. SSE turns are long-lived but small; 64 MiB leaves ample
/// headroom for real Responses API traffic.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// Response headers scoped to the *upstream* connection. They describe that
/// hop's framing and capabilities, so re-emitting them on our own re-framed
/// stream yields a response the client cannot parse (a stale `content-length`
/// beside a chunked body) or one that advertises upgrades we do not support.
///
/// `content-encoding` is deliberately absent: it is payload semantics, the relay
/// never decompresses, and dropping it would corrupt the body.
const STRIP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Copy only the response headers that are safe to re-emit on a new connection.
fn project_response_headers(upstream: &reqwest::header::HeaderMap) -> reqwest::header::HeaderMap {
    let mut projected = reqwest::header::HeaderMap::with_capacity(upstream.len());
    for (name, value) in upstream {
        if STRIP_RESPONSE_HEADERS.contains(&name.as_str()) {
            continue;
        }
        projected.append(name.clone(), value.clone());
    }
    projected
}

/// Build the relay's outbound client.
///
/// `tls` is supplied by the caller so tests can trust a local certificate while
/// production passes [`crate::tls::build_tls_config`]; `resolver` is the DNS
/// seam that carries the SSRF policy.
pub fn build_egress_client(
    tls: rustls::ClientConfig,
    resolver: Arc<dyn Resolve>,
    timeout_secs: u64,
) -> Client {
    build_egress_client_with_timeouts(
        tls,
        resolver,
        timeout_secs,
        DEFAULT_RESPONSE_HEADER_TIMEOUT_SECS,
    )
}

/// Same as [`build_egress_client`] with an explicit response-header deadline.
pub fn build_egress_client_with_timeouts(
    tls: rustls::ClientConfig,
    resolver: Arc<dyn Resolve>,
    timeout_secs: u64,
    response_header_timeout_secs: u64,
) -> Client {
    Client::builder()
        .use_preconfigured_tls(tls)
        // Redirects must be handled by the caller, not silently followed to a
        // host that never passed target validation or the DNS policy.
        .redirect(reqwest::redirect::Policy::none())
        // Egress must not be diverted by HTTP(S)_PROXY in the unit environment.
        .no_proxy()
        .dns_resolver(Arc::new(SharedResolver(resolver)))
        // Bounds only the wait for the status line and headers, so a streaming
        // body may still run up to the overall ceiling.
        .read_timeout(Duration::from_secs(response_header_timeout_secs))
        .timeout(Duration::from_secs(timeout_secs))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .expect("failed to build relay egress client")
}

/// `ClientBuilder::dns_resolver` needs a sized `Arc<R>`, so the trait object is
/// wrapped instead of being passed directly.
struct SharedResolver(Arc<dyn Resolve>);

impl Resolve for SharedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        self.0.resolve(name)
    }
}

/// Production client: shared TLS config plus the SSRF-safe system resolver.
pub fn build_production_client(timeout_secs: u64) -> Client {
    build_egress_client(
        crate::tls::build_tls_config(),
        Arc::new(crate::relay_resolver::SafeResolver::system()),
        timeout_secs,
    )
}

pub struct HttpsForwarder {
    client: Client,
    max_response_bytes: u64,
}

impl HttpsForwarder {
    pub fn new(client: Client) -> Self {
        Self::with_response_limit(client, DEFAULT_MAX_RESPONSE_BYTES)
    }

    /// Explicit response-body ceiling. The limit belongs to the forwarder, not
    /// the client: reqwest has no response-size knob, so it is enforced while
    /// the body streams.
    pub fn with_response_limit(client: Client, max_response_bytes: u64) -> Self {
        Self {
            client,
            max_response_bytes,
        }
    }

    /// Convert an authenticated relay request into a ready-to-send upstream
    /// request, or fail before touching the network.
    fn build(&self, request: ForwardRequest) -> Result<reqwest::RequestBuilder, ForwardError> {
        let target = Target::parse(&request.method, &request.target)
            .map_err(|_| ForwardError::InvalidTarget)?;
        let method = Method::from_bytes(target.method().as_bytes())
            .map_err(|_| ForwardError::InvalidTarget)?;

        let mut builder = self.client.request(method, target.url().clone());
        for [name, value] in request.headers {
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| ForwardError::InvalidHeader)?;
            let value = HeaderValue::from_str(&value).map_err(|_| ForwardError::InvalidHeader)?;
            builder = builder.header(name, value);
        }

        Ok(builder.body(request.body))
    }
}

impl Forwarder for HttpsForwarder {
    fn forward(
        &self,
        request: ForwardRequest,
    ) -> futures_util::future::BoxFuture<'static, Result<ForwardResponse, ForwardError>> {
        let built = self.build(request);
        let max_response_bytes = self.max_response_bytes;

        Box::pin(async move {
            let response = built?.send().await.map_err(classify)?;
            let status = response.status();
            let headers = project_response_headers(response.headers());
            // Hand the body back as a stream: SSE events must reach the caller
            // as they arrive, and no single response may be buffered in full.
            let body = response.bytes_stream().map_err(std::io::Error::other);
            Ok(ForwardResponse {
                status,
                headers,
                body: Box::pin(limit_stream(body, max_response_bytes)),
            })
        })
    }
}

/// Fail the stream once the relayed body exceeds `max_bytes`.
///
/// Enforced per chunk as bytes flow, so an oversized upstream is cut off mid
/// transfer instead of being buffered and measured afterwards.
fn limit_stream<S>(
    stream: S,
    max_bytes: u64,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>>,
{
    let mut relayed: u64 = 0;
    let mut tripped = false;
    stream.try_take_while(move |chunk| {
        let result = if tripped {
            Ok(false)
        } else {
            relayed = relayed.saturating_add(chunk.len() as u64);
            if relayed > max_bytes {
                tripped = true;
                Err(std::io::Error::other(format!(
                    "response body too large: over {max_bytes} bytes"
                )))
            } else {
                Ok(true)
            }
        };
        std::future::ready(result)
    })
}

/// Collapse a reqwest failure into a client-safe category. The original error
/// carries hostnames, resolved addresses and TLS details, so it is deliberately
/// dropped here rather than propagated.
fn classify(error: reqwest::Error) -> ForwardError {
    if error.is_timeout() {
        ForwardError::Timeout
    } else {
        ForwardError::Upstream
    }
}
