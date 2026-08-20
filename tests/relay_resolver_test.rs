use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

use codex_egress_relay::relay_resolver::{DnsLookup, LookupFuture, ResolverError, SafeResolver};
use reqwest::dns::Resolve;

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

#[allow(dead_code)]
fn _assert_future_is_send<T: Send>(_: Pin<Box<dyn Future<Output = T> + Send>>) {}
