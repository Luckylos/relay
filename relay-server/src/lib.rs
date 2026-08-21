//! Layered implementation of the signed HTTPS relay.
//!
//! The public aliases retain the protocol-facing module paths used by the
//! integration tests and the conformance runner while the implementation is
//! grouped by responsibility:
//!
//! - [`app`] owns the HTTP entrypoint, request parsing, and admission lifetime;
//! - [`protocol`] owns canonical signing and replay-aware authentication;
//! - [`egress`] owns target, DNS, TLS, and streaming forwarding policy.

pub mod app;
pub mod egress;
pub mod protocol;

// Compatibility aliases are deliberate: these are crate API paths, not an
// implementation duplicate. They let callers migrate to the layered tree
// without changing the signed wire contract or test fixtures.
pub use app::relay as https_relay;
pub use egress::{
    forwarder as https_forwarder, resolver as relay_resolver, safe_dns, target as relay_target, tls,
};
pub use protocol::{auth as relay_auth, signing as relay_protocol};
