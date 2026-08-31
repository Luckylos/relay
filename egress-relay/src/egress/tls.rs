//! Outbound TLS configuration.
//!
//! The whole point of this crate is that the ClientHello we emit is
//! byte-for-byte the one a real Codex CLI emits. That is achieved by using the
//! SAME crypto stack the real client uses: rustls 0.23 backed by the
//! **aws-lc-rs** provider (NOT ring).
//!
//! Why this matters — verified empirically by capturing the native codex
//! v0.145.0 binary's real ClientHello and comparing apples-to-apples against
//! this relay under identical conditions (same loopback sink, IP-literal SNI):
//!
//!   real codex JA4 : t13d1011h2_61a7ad8aa9b6_f9531d972513
//!
//! The reqwest `rustls-tls` feature pulls the `ring` provider, whose default
//! signature_algorithms set is MISSING `ecdsa_secp521r1_sha512` (0x0603). That
//! single missing sigalg was the ONLY byte that differed in the JA4 (the third,
//! extension+sigalg hash segment). aws-lc-rs advertises 0x0603, so its full
//! sigalg list — and therefore the JA4 — matches the real client exactly.
//!
//! We therefore build the rustls `ClientConfig` ourselves with the aws-lc-rs
//! provider and inject it via `reqwest`'s `use_preconfigured_tls`, using the
//! `*-no-provider` reqwest feature so `ring` is never linked in.
//!
//! ALPN offers `h2` then `http/1.1`, exactly as the real client, keeping the
//! JA4 ALPN marker `h2` and negotiating HTTP/2.

use std::sync::Arc;

/// The rustls `ClientConfig` every outbound path in this crate must use.
///
/// Kept separate from client construction so each caller can supply its own
/// resolver and redirect policy without duplicating — or accidentally diverging
/// from — the fingerprint-critical crypto/ALPN setup above.
pub fn build_tls_config() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws-lc-rs provider supports default protocol versions")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls
}
