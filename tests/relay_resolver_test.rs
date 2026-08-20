use std::error::Error;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use codex_egress_relay::relay_resolver::{DnsLookup, LookupFuture, ResolverError, SafeResolver};
use reqwest::dns::Resolve;

fn test_tls_config() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth()
}

struct StubLookup {
    addresses: Vec<IpAddr>,
}

impl DnsLookup for StubLookup {
    fn lookup(&self, hostname: &str) -> LookupFuture {
        assert_eq!(hostname, "api.example.com");
        let addresses = self.addresses.clone();
        Box::pin(async move { Ok(addresses) })
    }
}

struct FailingLookup;

impl DnsLookup for FailingLookup {
    fn lookup(&self, _hostname: &str) -> LookupFuture {
        Box::pin(async { Err(ResolverError::Lookup("dns unavailable".to_owned())) })
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(segments))
}

#[tokio::test]
async fn validates_dns_answers_before_exposing_socket_addresses() {
    let resolver = SafeResolver::from_lookup(StubLookup {
        addresses: vec![v4(1, 1, 1, 1), v6([0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888])],
    });

    let addresses = resolver.resolve_ips("api.example.com").await.unwrap();

    assert_eq!(
        addresses,
        vec![v4(1, 1, 1, 1), v6([0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888])]
    );
}

#[tokio::test]
async fn rejects_mixed_dns_answers_before_they_reach_reqwest() {
    let resolver = SafeResolver::from_lookup(StubLookup {
        addresses: vec![v4(1, 1, 1, 1), v4(10, 0, 0, 1)],
    });

    assert!(matches!(
        resolver.resolve_ips("api.example.com").await,
        Err(ResolverError::Policy(_))
    ));
}

#[tokio::test]
async fn maps_validated_ips_to_https_socket_addresses() {
    let resolver = SafeResolver::from_lookup(StubLookup {
        addresses: vec![v4(1, 1, 1, 1), v6([0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888])],
    });
    let name = "api.example.com".parse().unwrap();

    let addrs: Vec<SocketAddr> = resolver.resolve(name).await.unwrap().collect();

    assert_eq!(
        addrs,
        vec![
            SocketAddr::new(v4(1, 1, 1, 1), 443),
            SocketAddr::new(v6([0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888]), 443),
        ]
    );
}

#[tokio::test]
async fn propagates_dns_failures_without_fabricating_addresses() {
    let resolver = SafeResolver::from_lookup(FailingLookup);
    let name = "api.example.com".parse().unwrap();

    assert!(matches!(
        resolver.resolve(name).await,
        Err(error) if error.to_string().contains("dns unavailable")
    ));
}

#[tokio::test]
async fn system_lookup_rejects_localhost_after_resolution() {
    let resolver = SafeResolver::system();

    assert!(matches!(
        resolver.resolve_ips("localhost").await,
        Err(ResolverError::Policy(_))
    ));
}

#[tokio::test]
async fn configures_reqwest_to_use_safe_resolver_and_disable_proxies() {
    let client = SafeResolver::system()
        .configure(reqwest::Client::builder().use_preconfigured_tls(test_tls_config()))
        .build()
        .unwrap();

    let error = client
        .get("https://localhost/")
        .send()
        .await
        .expect_err("localhost must be rejected before a connection attempt");

    let mut causes = Vec::new();
    let mut source = error.source();
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }

    assert!(
        causes
            .iter()
            .any(|cause| cause.contains("DNS policy rejected")),
        "unexpected resolver error chain: {error}; causes: {causes:?}"
    );
}

#[allow(dead_code)]
fn _assert_future_is_send<T: Send>(_: Pin<Box<dyn Future<Output = T> + Send>>) {}
