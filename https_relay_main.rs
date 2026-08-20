mod relay_config;

use std::sync::Arc;

use codex_egress_relay::https_relay::{
    build_app, ForwardError, ForwardRequest, ForwardResponse, Forwarder, RelayState,
};
use codex_egress_relay::relay_auth::{AuthGate, AuthPolicy, KeyRing};
use futures_util::future::BoxFuture;
use relay_config::RelayConfig;

struct NoopForwarder;

impl Forwarder for NoopForwarder {
    fn forward(
        &self,
        _request: ForwardRequest,
    ) -> BoxFuture<'static, Result<ForwardResponse, ForwardError>> {
        Box::pin(async { Err(ForwardError::Unavailable) })
    }
}

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
    let app = build_app(RelayState::new(auth, Arc::new(NoopForwarder)));
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .unwrap_or_else(|error| panic!("relay bind error: {error}"));

    axum::serve(listener, app)
        .await
        .expect("relay server error");
}
