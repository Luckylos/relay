use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::relay_protocol::{
    base64url_decode, build_canonical_request, ProtocolError, RelaySigningInput,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPolicy {
    pub clock_skew_secs: i64,
}

impl AuthPolicy {
    pub const fn new(clock_skew_secs: i64) -> Self {
        Self { clock_skew_secs }
    }
}

#[derive(Debug, Default)]
pub struct KeyRing {
    keys: HashMap<String, Vec<u8>>,
}

impl KeyRing {
    pub fn insert(&mut self, key_id: impl Into<String>, secret: impl AsRef<[u8]>) {
        self.keys.insert(key_id.into(), secret.as_ref().to_vec());
    }

    fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.keys.get(key_id).map(Vec::as_slice)
    }
}

#[derive(Debug)]
pub struct RelayAuthRequest<'a> {
    pub signing: RelaySigningInput<'a>,
    pub signature: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub key_id: String,
    pub timestamp: i64,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Protocol(ProtocolError),
    TimestampOutsideWindow,
    UnknownKey,
    InvalidSignature,
    Replay,
}

#[derive(Debug, Default)]
struct InMemoryNonceStore {
    entries: HashMap<(String, String), i64>,
}

impl InMemoryNonceStore {
    fn check_and_record(&mut self, key_id: &str, nonce: &str, expires_at: i64, now: i64) -> bool {
        self.entries.retain(|_, expiry| *expiry > now);
        let key = (key_id.to_owned(), nonce.to_owned());
        if self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(key, expires_at);
        true
    }
}

#[derive(Debug)]
pub struct AuthGate {
    keys: KeyRing,
    policy: AuthPolicy,
    nonces: InMemoryNonceStore,
}

impl AuthGate {
    pub fn new(keys: KeyRing, policy: AuthPolicy) -> Self {
        Self {
            keys,
            policy,
            nonces: InMemoryNonceStore::default(),
        }
    }

    pub fn authenticate(
        &mut self,
        now: i64,
        request: RelayAuthRequest<'_>,
    ) -> Result<AuthContext, AuthError> {
        let signing = &request.signing;
        let canonical = build_canonical_request(signing).map_err(AuthError::Protocol)?;

        let skew = self.policy.clock_skew_secs.max(0);
        let delta = (now as i128 - signing.timestamp as i128).abs();
        if delta > skew as i128 {
            return Err(AuthError::TimestampOutsideWindow);
        }

        let secret = self.keys.get(signing.key_id).ok_or(AuthError::UnknownKey)?;
        let signature =
            base64url_decode(request.signature).map_err(|_| AuthError::InvalidSignature)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret).map_err(|_| AuthError::InvalidSignature)?;
        mac.update(canonical.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| AuthError::InvalidSignature)?;

        let expires_at = now.saturating_add(skew);
        if !self
            .nonces
            .check_and_record(signing.key_id, signing.nonce, expires_at, now)
        {
            return Err(AuthError::Replay);
        }

        Ok(AuthContext {
            key_id: signing.key_id.to_owned(),
            timestamp: signing.timestamp,
            nonce: signing.nonce.to_owned(),
        })
    }
}
