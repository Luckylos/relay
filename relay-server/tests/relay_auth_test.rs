use codex_egress_relay::relay_auth::{AuthError, AuthGate, AuthPolicy, KeyRing, RelayAuthRequest};
use codex_egress_relay::relay_protocol::{ProtocolError, RelaySigningInput};

const NOW: i64 = 1_700_000_000;
const CURRENT_KEY: &[u8] = b"current-fixture-key";
const PREVIOUS_KEY: &[u8] = b"previous-fixture-key";

struct TestRequest {
    version: u8,
    key_id: String,
    timestamp: i64,
    nonce: String,
    method: String,
    target: String,
    headers: Vec<[String; 2]>,
    body: Vec<u8>,
    signature: String,
}

impl TestRequest {
    fn signed(key_id: &str, secret: &[u8]) -> Self {
        let mut request = Self {
            version: 1,
            key_id: key_id.to_owned(),
            timestamp: NOW,
            nonce: "AQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
            method: "POST".to_owned(),
            target: "https://api.example.com/v1/responses".to_owned(),
            headers: vec![["content-type".to_owned(), "application/json".to_owned()]],
            body: br#"{"model":"fixture"}"#.to_vec(),
            signature: String::new(),
        };
        request.signature = request.sign(secret);
        request
    }

    fn sign(&self, secret: &[u8]) -> String {
        let input = RelaySigningInput {
            version: self.version,
            key_id: &self.key_id,
            timestamp: self.timestamp,
            nonce: &self.nonce,
            method: &self.method,
            target: &self.target,
            headers: &self.headers,
            body: &self.body,
        };
        codex_egress_relay::relay_protocol::sign_relay_request(&input, secret).unwrap()
    }

    fn auth_request(&self) -> RelayAuthRequest<'_> {
        RelayAuthRequest {
            signing: RelaySigningInput {
                version: self.version,
                key_id: &self.key_id,
                timestamp: self.timestamp,
                nonce: &self.nonce,
                method: &self.method,
                target: &self.target,
                headers: &self.headers,
                body: &self.body,
            },
            signature: &self.signature,
        }
    }
}

fn gate() -> AuthGate {
    let mut keys = KeyRing::default();
    keys.insert("current", CURRENT_KEY);
    keys.insert("previous", PREVIOUS_KEY);
    AuthGate::new(keys, AuthPolicy::new(300))
}

#[test]
fn accepts_a_valid_signature() {
    let mut gate = gate();
    let request = TestRequest::signed("current", CURRENT_KEY);

    let context = gate.authenticate(NOW, request.auth_request()).unwrap();

    assert_eq!(context.key_id, "current");
    assert_eq!(context.timestamp, NOW);
    assert_eq!(context.nonce, request.nonce);
}

#[test]
fn accepts_current_and_previous_key_slots() {
    let mut gate = gate();
    let current = TestRequest::signed("current", CURRENT_KEY);
    let previous = TestRequest::signed("previous", PREVIOUS_KEY);

    assert!(gate.authenticate(NOW, current.auth_request()).is_ok());
    assert!(gate.authenticate(NOW, previous.auth_request()).is_ok());
}

#[test]
fn rejects_an_unknown_key_without_consuming_the_nonce() {
    let mut gate = gate();
    let request = TestRequest::signed("retired", b"retired-key");

    assert!(matches!(
        gate.authenticate(NOW, request.auth_request()),
        Err(AuthError::UnknownKey)
    ));

    let valid = TestRequest::signed("current", CURRENT_KEY);
    assert!(gate.authenticate(NOW, valid.auth_request()).is_ok());
}

#[test]
fn rejects_timestamps_outside_the_clock_window() {
    let mut gate = gate();
    let mut old = TestRequest::signed("current", CURRENT_KEY);
    old.timestamp = NOW - 301;
    let mut future = TestRequest::signed("current", CURRENT_KEY);
    future.timestamp = NOW + 301;

    assert!(matches!(
        gate.authenticate(NOW, old.auth_request()),
        Err(AuthError::TimestampOutsideWindow)
    ));
    assert!(matches!(
        gate.authenticate(NOW, future.auth_request()),
        Err(AuthError::TimestampOutsideWindow)
    ));
}

#[test]
fn rejects_an_invalid_hmac() {
    let mut gate = gate();
    let mut request = TestRequest::signed("current", CURRENT_KEY);
    request.signature.replace_range(0..1, "A");

    assert!(matches!(
        gate.authenticate(NOW, request.auth_request()),
        Err(AuthError::InvalidSignature)
    ));
}

#[test]
fn an_invalid_signature_does_not_poison_the_nonce() {
    let mut gate = gate();
    let mut invalid = TestRequest::signed("current", CURRENT_KEY);
    invalid.signature.replace_range(0..1, "A");
    assert!(matches!(
        gate.authenticate(NOW, invalid.auth_request()),
        Err(AuthError::InvalidSignature)
    ));

    let valid = TestRequest::signed("current", CURRENT_KEY);
    assert!(gate.authenticate(NOW, valid.auth_request()).is_ok());
}

#[test]
fn rejects_a_replayed_nonce_after_the_first_success() {
    let mut gate = gate();
    let request = TestRequest::signed("current", CURRENT_KEY);

    assert!(gate.authenticate(NOW, request.auth_request()).is_ok());
    assert!(matches!(
        gate.authenticate(NOW, request.auth_request()),
        Err(AuthError::Replay)
    ));
}

#[test]
fn rejects_malformed_signature_without_consuming_the_nonce() {
    let mut gate = gate();
    let mut malformed = TestRequest::signed("current", CURRENT_KEY);
    malformed.signature.push('=');
    assert!(matches!(
        gate.authenticate(NOW, malformed.auth_request()),
        Err(AuthError::InvalidSignature)
    ));

    let valid = TestRequest::signed("current", CURRENT_KEY);
    assert!(gate.authenticate(NOW, valid.auth_request()).is_ok());
}

#[test]
fn rejects_invalid_protocol_version_before_signature_verification() {
    let mut gate = gate();
    let mut request = TestRequest::signed("current", CURRENT_KEY);
    request.version = 2;

    assert!(matches!(
        gate.authenticate(NOW, request.auth_request()),
        Err(AuthError::Protocol(ProtocolError::UnsupportedVersion(2)))
    ));
}

#[test]
fn rejects_invalid_nonce_before_recording_it() {
    let mut gate = gate();
    let mut request = TestRequest::signed("current", CURRENT_KEY);
    request.nonce = "AQ".to_owned();

    assert!(matches!(
        gate.authenticate(NOW, request.auth_request()),
        Err(AuthError::Protocol(ProtocolError::InvalidField("nonce")))
    ));
}

const SKEW: i64 = 60;

fn skewed_gate() -> AuthGate {
    let mut keys = KeyRing::default();
    keys.insert("current", CURRENT_KEY);
    AuthGate::new(keys, AuthPolicy::new(SKEW))
}

fn signed_at(timestamp: i64) -> TestRequest {
    let mut request = TestRequest::signed("current", CURRENT_KEY);
    request.timestamp = timestamp;
    request.signature = request.sign(CURRENT_KEY);
    request
}

/// A nonce must stay blocked for as long as its own timestamp is acceptable.
///
/// A request signed at `ts` is accepted across `[ts - skew, ts + skew]`, a span
/// `2 * skew` wide. Expiring the cache entry relative to when it was *observed*
/// rather than to the end of that span leaves a replay hole: a request first
/// seen early in its own validity span is forgotten while still replayable.
#[test]
fn a_nonce_stays_blocked_across_its_whole_validity_span() {
    let mut gate = skewed_gate();
    let request = signed_at(NOW);

    // Earliest instant the relay accepts it: the signer's clock is a full skew
    // ahead of the relay's, which the +/- window explicitly permits.
    gate.authenticate(NOW - SKEW, request.auth_request())
        .expect("first use at the earliest acceptable instant must succeed");

    for offset in [-SKEW + 1, -SKEW / 2, -1, 0, 1, SKEW / 2, SKEW - 1, SKEW] {
        let now = NOW + offset;
        assert!(
            (now - request.timestamp).abs() <= SKEW,
            "probe at ts{offset:+} must itself still be inside the accept window"
        );
        assert!(
            matches!(
                gate.authenticate(now, request.auth_request()),
                Err(AuthError::Replay)
            ),
            "replay at ts{offset:+} was not blocked while the timestamp is still in window"
        );
    }
}

/// The replay cache must stay bounded. Once a timestamp is outside the window
/// the request is rejected on the timestamp alone, so retaining its nonce
/// forever would only leak memory.
#[test]
fn a_nonce_is_reusable_once_its_original_timestamp_is_out_of_window() {
    let mut gate = skewed_gate();
    let first = signed_at(NOW);
    gate.authenticate(NOW, first.auth_request())
        .expect("first use must succeed");

    let later = NOW + 10 * SKEW;
    let mut second = signed_at(later);
    second.nonce = first.nonce.clone();
    second.signature = second.sign(CURRENT_KEY);

    assert!(
        gate.authenticate(later, second.auth_request()).is_ok(),
        "a nonce whose original request can no longer be accepted must not be retained"
    );
}
