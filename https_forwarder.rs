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

use reqwest::dns::Resolve;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, Method};

use crate::https_relay::{ForwardError, ForwardRequest, ForwardResponse, Forwarder};
use crate::relay_target::Target;

/// Default ceiling for a whole upstream request/response exchange.
pub const DEFAULT_TIMEOUT_SECS: u64 = 600;

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
    Client::builder()
        .use_preconfigured_tls(tls)
        // Redirects must be handled by the caller, not silently followed to a
        // host that never passed target validation or the DNS policy.
        .redirect(reqwest::redirect::Policy::none())
        // Egress must not be diverted by HTTP(S)_PROXY in the unit environment.
        .no_proxy()
        .dns_resolver(Arc::new(SharedResolver(resolver)))
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
}

impl HttpsForwarder {
    pub fn new(client: Client) -> Self {
        Self { client }
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

        Box::pin(async move {
            let response = built?.send().await.map_err(classify)?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.map_err(classify)?;
            Ok(ForwardResponse {
                status,
                headers,
                body,
            })
        })
    }
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
