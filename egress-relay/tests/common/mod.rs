//! Shared fixtures for the relay integration tests.
//!
//! Lives in `tests/common/` (a directory, so Cargo treats it as a module rather
//! than another test binary). Each test binary uses a subset, hence the
//! crate-level `dead_code` allowance.
#![allow(dead_code)]

use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use egress_relay::relay_resolver::{DnsLookup, LookupFuture, SafeResolver};
use futures_util::StreamExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A self-signed leaf for `api.example.com`, returned with its key so the test
/// client can trust it as its own root. `danger_accept_invalid_certs` is not an
/// option here: reqwest cannot weaken a `use_preconfigured_tls` config, and the
/// production path must keep real certificate verification anyway.
pub struct Issued {
    pub certificate: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

pub fn issue_upstream_certificate() -> Issued {
    let certified = rcgen::generate_simple_self_signed(vec!["api.example.com".to_owned()]).unwrap();
    Issued {
        certificate: CertificateDer::from(certified.cert.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        )),
    }
}

pub fn client_tls_config(trusted: Option<CertificateDer<'static>>) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    match trusted {
        Some(certificate) => root_store.add(certificate).unwrap(),
        None => root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

pub fn server_tls_config(issued: Issued) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![issued.certificate], issued.key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Test seam that stands in for a resolver whose DNS answers are already
/// trusted, so forwarding mechanics can be exercised against a loopback
/// upstream. Production never uses this: it uses `SafeResolver`.
pub struct PinnedResolver(pub SocketAddr);

impl Resolve for PinnedResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let address = self.0;
        Box::pin(async move {
            let addresses: Addrs = Box::new(std::iter::once(address));
            Ok(addresses)
        })
    }
}

/// DNS answer injected into the real `SafeResolver` so the SSRF policy runs on
/// a controlled result instead of the host resolver.
pub struct FixedLookup(pub Vec<IpAddr>);

impl DnsLookup for FixedLookup {
    fn lookup(&self, _hostname: &str) -> LookupFuture {
        let addresses = self.0.clone();
        Box::pin(async move { Ok(addresses) })
    }
}

pub fn safe_resolver_for(addresses: Vec<IpAddr>) -> SafeResolver {
    SafeResolver::from_lookup(FixedLookup(addresses))
}

/// Drain a forward stream into one buffer. Only for tests that assert on the
/// whole body; streaming tests must poll chunk by chunk instead.
pub async fn collect_body(
    mut body: egress_relay::https_relay::ForwardStream,
) -> Result<Bytes, std::io::Error> {
    let mut collected = Vec::new();
    while let Some(chunk) = body.next().await {
        collected.extend_from_slice(&chunk?);
    }
    Ok(Bytes::from(collected))
}

/// Build a validly signed request for the `/v1/forward` entrypoint.
///
/// The nonce is caller-chosen because concurrency tests need several requests
/// in flight at once: reusing one nonce would trip the replay gate, so a test
/// would read as "admission refused it" when in fact auth did.
pub fn signed_relay_request(
    nonce: &str,
    secret: &[u8],
    now: i64,
) -> axum::http::Request<axum::body::Body> {
    use egress_relay::relay_protocol::{
        base64url_encode, canonicalize_headers, sha256_base64url, sign_relay_request,
        RelaySigningInput,
    };

    let method = "POST";
    let target = "https://api.example.com/v1/responses";
    let headers = vec![["content-type".to_owned(), "application/json".to_owned()]];
    let body = br#"{"model":"fixture"}"#.to_vec();
    let signature = sign_relay_request(
        &RelaySigningInput {
            version: 1,
            key_id: "current",
            timestamp: now,
            nonce,
            method,
            target,
            headers: &headers,
            body: &body,
        },
        secret,
    )
    .unwrap();
    let header_block = canonicalize_headers(&headers).unwrap();

    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/forward")
        .header("content-type", "application/octet-stream")
        .header("x-codex-relay-version", "1")
        .header("x-codex-relay-key-id", "current")
        .header("x-codex-relay-timestamp", now.to_string())
        .header("x-codex-relay-nonce", nonce)
        .header("x-codex-relay-method", method)
        .header("x-codex-relay-target", base64url_encode(target.as_bytes()))
        .header("x-codex-relay-body-sha256", sha256_base64url(&body))
        .header(
            "x-codex-relay-headers",
            base64url_encode(header_block.as_bytes()),
        )
        .header("x-codex-relay-signature", signature)
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// Encode one HTTP/1.1 chunked-transfer chunk.
pub fn http_chunk(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:x}\r\n", payload.len()).into_bytes();
    framed.extend_from_slice(payload);
    framed.extend_from_slice(b"\r\n");
    framed
}
