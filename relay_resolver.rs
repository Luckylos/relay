use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::safe_dns::{validate_resolved_addresses, DnsPolicyError};

pub type LookupFuture = Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, ResolverError>> + Send>>;

pub trait DnsLookup: Send + Sync {
    fn lookup(&self, hostname: &str) -> LookupFuture;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverError {
    Lookup(String),
    Policy(DnsPolicyError),
}

impl fmt::Display for ResolverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(message) => write!(formatter, "DNS lookup failed: {message}"),
            Self::Policy(error) => write!(formatter, "DNS policy rejected the result: {error:?}"),
        }
    }
}

impl Error for ResolverError {}

#[derive(Clone)]
pub struct SafeResolver {
    lookup: Arc<dyn DnsLookup>,
}

impl SafeResolver {
    pub fn system() -> Self {
        Self::from_lookup(SystemDnsLookup)
    }

    pub fn from_lookup<L>(lookup: L) -> Self
    where
        L: DnsLookup + 'static,
    {
        Self {
            lookup: Arc::new(lookup),
        }
    }

    pub async fn resolve_ips(&self, hostname: &str) -> Result<Vec<IpAddr>, ResolverError> {
        let addresses = self.lookup.lookup(hostname).await?;
        validate_resolved_addresses(&addresses).map_err(ResolverError::Policy)
    }
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        let hostname = name.as_str().to_owned();

        Box::pin(async move {
            let addresses = resolver.resolve_ips(&hostname).await?;
            let socket_addresses: Addrs = Box::new(
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address, 443)),
            );
            Ok(socket_addresses)
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDnsLookup;

impl DnsLookup for SystemDnsLookup {
    fn lookup(&self, hostname: &str) -> LookupFuture {
        let hostname = hostname.to_owned();
        Box::pin(async move {
            let resolved = tokio::net::lookup_host((hostname.as_str(), 443))
                .await
                .map_err(|error| ResolverError::Lookup(error.to_string()))?;
            let mut addresses = Vec::new();
            for address in resolved {
                let ip = address.ip();
                if !addresses.contains(&ip) {
                    addresses.push(ip);
                }
            }
            Ok(addresses)
        })
    }
}
