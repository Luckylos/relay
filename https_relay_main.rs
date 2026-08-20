mod relay_config;

use std::sync::Arc;

use codex_egress_relay::https_forwarder::{
    build_production_client, HttpsForwarder, DEFAULT_TIMEOUT_SECS,
};
use codex_egress_relay::https_relay::{build_app, RelayState};
use codex_egress_relay::relay_auth::{AuthGate, AuthPolicy, KeyRing};
use relay_config::RelayConfig;

#[tokio::main]
async fn main() {
    let config =
        RelayConfig::from_env().unwrap_or_else(|error| panic!("relay config error: {error}"));

    let mut keys = KeyRing::default();
    keys.insert(&config.current_key_id, &config.current_secret);
    if let Some((key_id, secret)) = &config.previous_key {
        keys.insert(key_id, secret);
    }

    let auth = AuthGate::new(keys, AuthPolicy::new(config.clock_skew_secs));
    // Egress: shared rustls/aws-lc-rs fingerprint config, SSRF-safe resolver,
    // no proxy env override, no automatic redirects.
    let forwarder = HttpsForwarder::new(build_production_client(DEFAULT_TIMEOUT_SECS));
    let app = build_app(RelayState::new(auth, Arc::new(forwarder)));
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .unwrap_or_else(|error| panic!("relay bind error: {error}"));

    axum::serve(listener, app)
        .await
        .expect("relay server error");
}
