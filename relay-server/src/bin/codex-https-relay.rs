mod relay_config;

use std::sync::Arc;

use codex_https_relay::app::relay::{build_app, RelayState};
use codex_https_relay::egress::forwarder::{
    build_production_client_with_stall, HttpsForwarder, DEFAULT_TIMEOUT_SECS,
};
use codex_https_relay::protocol::auth::{AuthGate, AuthPolicy, KeyRing};
use relay_config::RelayConfig;

#[tokio::main]
async fn main() {
    // A config error is an operator mistake in the unit or env file, not a bug:
    // report it on stderr and exit non-zero rather than panicking. A panic here
    // buries the offending variable under a backtrace, and with
    // `Restart=on-failure` a single typo becomes an unexplained restart loop.
    let config = match RelayConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("relay config error: {error}");
            std::process::exit(2);
        }
    };

    let mut keys = KeyRing::default();
    keys.insert(&config.current_key_id, &config.current_secret);
    if let Some((key_id, secret)) = &config.previous_key {
        keys.insert(key_id, secret);
    }

    let auth = AuthGate::new(keys, AuthPolicy::new(config.clock_skew_secs));
    // Egress: shared rustls/aws-lc-rs fingerprint config, SSRF-safe resolver,
    // no proxy env override, no automatic redirects.
    let forwarder = HttpsForwarder::with_response_limit(
        build_production_client_with_stall(
            DEFAULT_TIMEOUT_SECS,
            config.stream_stall_timeout_secs,
            config.connect_timeout_secs,
        ),
        config.max_response_bytes,
    )
    .with_response_header_timeout(std::time::Duration::from_secs(
        config.response_header_timeout_secs,
    ));
    let app = build_app(
        RelayState::new(auth, Arc::new(forwarder))
            .with_max_body_bytes(config.max_body_bytes)
            .with_max_concurrency(config.max_concurrency),
    );
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .unwrap_or_else(|error| panic!("relay bind error: {error}"));

    axum::serve(listener, app)
        .await
        .expect("relay server error");
}
