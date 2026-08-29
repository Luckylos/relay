use std::net::SocketAddr;

use egress_relay::app::relay::{DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_CONCURRENCY};
use egress_relay::egress::forwarder::{
    DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_RESPONSE_HEADER_TIMEOUT_SECS,
    DEFAULT_STREAM_STALL_TIMEOUT_SECS,
};

pub struct RelayConfig {
    pub listen_addr: SocketAddr,
    pub clock_skew_secs: i64,
    pub current_key_id: String,
    pub current_secret: Vec<u8>,
    pub previous_key: Option<(String, Vec<u8>)>,
    /// Deadline for the upstream's status line. Reasoning turns can stall here
    /// for a long time before emitting anything, so this is operator-tunable.
    pub response_header_timeout_secs: u64,
    /// Budget for silence *between* response chunks once streaming has begun.
    pub stream_stall_timeout_secs: u64,
    /// Budget for opening the upstream connection. No other deadline can cover
    /// this: they all start counting once a socket exists.
    pub connect_timeout_secs: u64,
    /// Ceiling on an accepted request body.
    pub max_body_bytes: usize,
    /// Ceiling on a single relayed response body.
    pub max_response_bytes: u64,
    /// Cap on requests in flight, refused as `relay_busy` once reached.
    pub max_concurrency: usize,
}

impl RelayConfig {
    pub fn from_env() -> Result<Self, String> {
        let listen_addr = required("CODEX_RELAY_LISTEN_ADDR")?
            .parse()
            .map_err(|_| "CODEX_RELAY_LISTEN_ADDR is not a valid socket address".to_owned())?;
        let clock_skew_secs = parse_clock_skew(std::env::var("CODEX_RELAY_CLOCK_SKEW_SECS").ok())?;
        let current_key_id = validate_key_id(&required("CODEX_RELAY_CURRENT_KEY_ID")?)?;
        let current_secret = required("CODEX_RELAY_CURRENT_SECRET")?.into_bytes();

        let previous_key_id = std::env::var("CODEX_RELAY_PREVIOUS_KEY_ID").ok();
        let previous_secret = std::env::var("CODEX_RELAY_PREVIOUS_SECRET").ok();
        let previous_key = match (previous_key_id, previous_secret) {
            (None, None) => None,
            (Some(key_id), Some(secret)) => Some((validate_key_id(&key_id)?, secret.into_bytes())),
            _ => return Err(
                "CODEX_RELAY_PREVIOUS_KEY_ID and CODEX_RELAY_PREVIOUS_SECRET must be set together"
                    .to_owned(),
            ),
        };

        let response_header_timeout_secs = parse_timeout_secs(
            "CODEX_RELAY_RESPONSE_HEADER_TIMEOUT_SECS",
            DEFAULT_RESPONSE_HEADER_TIMEOUT_SECS,
        )?;
        let stream_stall_timeout_secs = parse_timeout_secs(
            "CODEX_RELAY_STREAM_STALL_TIMEOUT_SECS",
            DEFAULT_STREAM_STALL_TIMEOUT_SECS,
        )?;
        let connect_timeout_secs = parse_timeout_secs(
            "CODEX_RELAY_CONNECT_TIMEOUT_SECS",
            DEFAULT_CONNECT_TIMEOUT_SECS,
        )?;
        // Same fail-closed parse as the deadlines: these are positive integers
        // whose units are bytes rather than seconds.
        let max_body_bytes = usize::try_from(parse_timeout_secs(
            "CODEX_RELAY_MAX_BODY_BYTES",
            DEFAULT_MAX_BODY_BYTES as u64,
        )?)
        .map_err(|_| {
            "CODEX_RELAY_MAX_BODY_BYTES exceeds this platform's addressable size".to_owned()
        })?;
        let max_response_bytes =
            parse_timeout_secs("CODEX_RELAY_MAX_RESPONSE_BYTES", DEFAULT_MAX_RESPONSE_BYTES)?;
        let max_concurrency = usize::try_from(parse_timeout_secs(
            "CODEX_RELAY_MAX_CONCURRENCY",
            DEFAULT_MAX_CONCURRENCY as u64,
        )?)
        .map_err(|_| {
            "CODEX_RELAY_MAX_CONCURRENCY exceeds this platform's addressable size".to_owned()
        })?;

        Ok(Self {
            listen_addr,
            clock_skew_secs,
            current_key_id,
            current_secret,
            previous_key,
            response_header_timeout_secs,
            stream_stall_timeout_secs,
            connect_timeout_secs,
            max_body_bytes,
            max_response_bytes,
            max_concurrency,
        })
    }
}

fn required(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn validate_key_id(value: &str) -> Result<String, String> {
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err("relay key id must be non-empty and contain no line breaks".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_clock_skew(value: Option<String>) -> Result<i64, String> {
    let value = value.unwrap_or_else(|| "60".to_owned());
    let parsed = value
        .parse::<i64>()
        .map_err(|_| "CODEX_RELAY_CLOCK_SKEW_SECS must be a positive integer".to_owned())?;
    if parsed <= 0 {
        return Err("CODEX_RELAY_CLOCK_SKEW_SECS must be a positive integer".to_owned());
    }
    Ok(parsed)
}

/// Parse a positive integer override, falling back to the compiled default.
///
/// Used for both deadlines and byte ceilings. Fails closed on a malformed or
/// zero value rather than silently substituting the default: a typo in a unit
/// file must not quietly change an egress deadline or a resource limit.
fn parse_timeout_secs(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(value) if value.is_empty() => Ok(default),
        Ok(value) => {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| format!("{name} must be a positive integer"))?;
            if parsed == 0 {
                return Err(format!("{name} must be a positive integer"));
            }
            Ok(parsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_skew_defaults_to_sixty_seconds() {
        assert_eq!(parse_clock_skew(None).unwrap(), 60);
    }

    #[test]
    fn clock_skew_rejects_zero_negative_and_non_numeric_values() {
        for value in [
            Some("0".to_owned()),
            Some("-1".to_owned()),
            Some("bad".to_owned()),
        ] {
            assert!(parse_clock_skew(value).is_err());
        }
    }

    #[test]
    fn key_id_rejects_line_breaks_and_empty_values() {
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id("current\nkey").is_err());
        assert_eq!(validate_key_id("current").unwrap(), "current");
    }

    /// An unset or blank override falls back to the compiled default, but a
    /// malformed or zero one fails closed.
    ///
    /// The distinction matters because these values are resource limits and
    /// egress deadlines: silently substituting a default for `MAX_CONCURRENCY=0`
    /// or a typo'd `CONNECT_TIMEOUT_SECS` would let a unit-file mistake change
    /// the relay's admission and timeout behaviour with no signal at all.
    #[test]
    fn overrides_fall_back_when_absent_and_fail_closed_when_invalid() {
        // Absent and empty both mean "operator expressed no opinion".
        std::env::remove_var("CODEX_RELAY_TEST_KNOB");
        assert_eq!(parse_timeout_secs("CODEX_RELAY_TEST_KNOB", 42).unwrap(), 42);
        std::env::set_var("CODEX_RELAY_TEST_KNOB", "");
        assert_eq!(parse_timeout_secs("CODEX_RELAY_TEST_KNOB", 42).unwrap(), 42);

        // A real value wins over the default.
        std::env::set_var("CODEX_RELAY_TEST_KNOB", "7");
        assert_eq!(parse_timeout_secs("CODEX_RELAY_TEST_KNOB", 42).unwrap(), 7);

        // Zero and non-numeric must fail, never degrade to the default.
        for bad in ["0", "-1", "10s", "abc", "1.5"] {
            std::env::set_var("CODEX_RELAY_TEST_KNOB", bad);
            assert!(
                parse_timeout_secs("CODEX_RELAY_TEST_KNOB", 42).is_err(),
                "{bad:?} must be rejected rather than silently defaulted"
            );
        }
        std::env::remove_var("CODEX_RELAY_TEST_KNOB");
    }
}
