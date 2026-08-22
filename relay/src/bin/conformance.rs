//! Cross-language conformance runner for relay protocol v1.
//!
//! Reads the vector payload from stdin (see `protocol/conformance.py`) and emits
//! one JSON object mapping vector name -> {canonical, signature}. The Python
//! driver diffs this against the Worker's TypeScript output; any disagreement in
//! canonical form or HMAC fails CI.
//!
//! This exists so the three independent protocol implementations cannot drift
//! silently — before the monorepo they only shared a hand-copied fixture.

use std::collections::BTreeMap;
use std::io::Read;

use codex_https_relay::protocol::signing::{
    build_canonical_request, sign_relay_request, RelaySigningInput,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Payload {
    secret: String,
    nonce: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    key_id: String,
    timestamp: i64,
    method: String,
    target: String,
    headers: Vec<[String; 2]>,
    body_utf8: String,
}

#[derive(Debug, Serialize)]
struct Outcome {
    canonical: String,
    signature: String,
}

fn main() {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .expect("read stdin payload");
    let payload: Payload = serde_json::from_str(&raw).expect("parse payload");

    let mut results: BTreeMap<String, Outcome> = BTreeMap::new();
    for vector in &payload.vectors {
        let body = vector.body_utf8.as_bytes();
        let input = RelaySigningInput {
            version: 1,
            key_id: &vector.key_id,
            timestamp: vector.timestamp,
            nonce: &payload.nonce,
            method: &vector.method,
            target: &vector.target,
            headers: &vector.headers,
            body,
        };

        let canonical = build_canonical_request(&input)
            .unwrap_or_else(|error| panic!("vector {}: canonical failed: {error:?}", vector.name));
        let signature = sign_relay_request(&input, payload.secret.as_bytes())
            .unwrap_or_else(|error| panic!("vector {}: signing failed: {error:?}", vector.name));

        results.insert(
            vector.name.clone(),
            Outcome {
                canonical,
                signature,
            },
        );
    }

    println!(
        "{}",
        serde_json::to_string(&results).expect("serialize results")
    );
}
