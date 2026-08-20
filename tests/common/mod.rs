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
use codex_egress_relay::relay_resolver::{DnsLookup, LookupFuture, SafeResolver};
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
    mut body: codex_egress_relay::https_relay::ForwardStream,
) -> Result<Bytes, std::io::Error> {
    let mut collected = Vec::new();
    while let Some(chunk) = body.next().await {
        collected.extend_from_slice(&chunk?);
    }
    Ok(Bytes::from(collected))
}

/// Encode one HTTP/1.1 chunked-transfer chunk.
pub fn http_chunk(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:x}\r\n", payload.len()).into_bytes();
    framed.extend_from_slice(payload);
    framed.extend_from_slice(b"\r\n");
    framed
}
