use std::fs;

use egress_relay::relay_protocol::{
    base64url_decode, base64url_encode, build_canonical_request, canonicalize_headers,
    sha256_base64url, sign_relay_request, ProtocolError, RelaySigningInput,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    version: u8,
    key_id: String,
    timestamp: i64,
    nonce: String,
    method: String,
    target: String,
    headers: Vec<[String; 2]>,
    body_utf8: String,
    canonical_header_block: String,
    canonical_header_block_b64: String,
    target_b64: String,
    body_sha256: String,
    canonical_request: String,
    secret: String,
    signature: String,
}

fn fixture() -> Fixture {
    let raw = fs::read_to_string("tests/fixtures/relay-protocol-v1.json").unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn input<'a>(fixture: &'a Fixture, body: &'a [u8]) -> RelaySigningInput<'a> {
    RelaySigningInput {
        version: fixture.version,
        key_id: &fixture.key_id,
        timestamp: fixture.timestamp,
        nonce: &fixture.nonce,
        method: &fixture.method,
        target: &fixture.target,
        headers: &fixture.headers,
        body,
    }
}

#[test]
fn matches_shared_canonical_request_and_hmac_fixture() {
    let vector = fixture();
    let body = vector.body_utf8.as_bytes();
    let request = input(&vector, body);

    assert_eq!(
        canonicalize_headers(&vector.headers).unwrap(),
        vector.canonical_header_block
    );
    assert_eq!(
        base64url_encode(vector.target.as_bytes()),
        vector.target_b64
    );
    assert_eq!(
        base64url_encode(vector.canonical_header_block.as_bytes()),
        vector.canonical_header_block_b64
    );
    assert_eq!(sha256_base64url(body), vector.body_sha256);
    assert_eq!(
        build_canonical_request(&request).unwrap(),
        vector.canonical_request
    );
    assert_eq!(
        sign_relay_request(&request, vector.secret.as_bytes()).unwrap(),
        vector.signature
    );
}

#[test]
fn rejects_unknown_protocol_versions() {
    let vector = fixture();
    let body = vector.body_utf8.clone().into_bytes();
    let mut request = input(&vector, &body);
    request.version = 2;

    assert!(matches!(
        build_canonical_request(&request),
        Err(ProtocolError::UnsupportedVersion(2))
    ));
}

#[test]
fn rejects_duplicate_canonical_header_names() {
    let result = canonicalize_headers(&[
        ["X-Test".to_owned(), "one".to_owned()],
        ["x-test".to_owned(), "two".to_owned()],
    ]);

    assert!(matches!(result, Err(ProtocolError::DuplicateHeader(name)) if name == "x-test"));
}

#[test]
fn rejects_illegal_header_names_and_crlf_values() {
    assert!(matches!(
        canonicalize_headers(&[["X Bad".to_owned(), "value".to_owned()]]),
        Err(ProtocolError::InvalidHeaderName(_))
    ));
    assert!(matches!(
        canonicalize_headers(&[["x-test".to_owned(), "ok\r\nforged: yes".to_owned()]]),
        Err(ProtocolError::InvalidHeaderValue)
    ));
}

#[test]
fn normalizes_header_whitespace_without_changing_name() {
    assert_eq!(
        canonicalize_headers(&[[
            "X-Test".to_owned(),
            " \talpha\t  beta   gamma \t".to_owned(),
        ]])
        .unwrap(),
        "x-test:alpha beta gamma\n"
    );
}

#[test]
fn rejects_padded_or_malformed_base64url() {
    let vector = fixture();
    assert!(matches!(
        base64url_decode(&format!("{}=", vector.signature)),
        Err(ProtocolError::InvalidBase64Url)
    ));
    assert!(matches!(
        base64url_decode("a"),
        Err(ProtocolError::InvalidBase64Url)
    ));
    assert!(matches!(
        base64url_decode("not+base64"),
        Err(ProtocolError::InvalidBase64Url)
    ));
}

#[test]
fn changes_body_digest_and_signature_when_one_body_byte_changes() {
    let vector = fixture();
    let mut body = vector.body_utf8.clone().into_bytes();
    let original_digest = sha256_base64url(&body);
    let last = body.len() - 1;
    body[last] ^= 1;
    let changed_digest = sha256_base64url(&body);
    let request = input(&vector, &body);

    assert_ne!(changed_digest, original_digest);
    assert_ne!(
        sign_relay_request(&request, vector.secret.as_bytes()).unwrap(),
        vector.signature
    );
}

#[test]
fn signs_non_ascii_targets_after_utf8_encoding() {
    let vector = fixture();
    let body = b"";
    let request = RelaySigningInput {
        target: "https://例え.テスト/v1/路径?q=雪",
        body,
        ..input(&vector, body)
    };
    let canonical = build_canonical_request(&request).unwrap();
    let target_line = canonical.lines().nth(5).unwrap();

    assert_eq!(
        target_line,
        "aHR0cHM6Ly_kvovjgYgu44OG44K544OIL3YxL-i3r-W-hD9xPembqg"
    );
    assert_ne!(
        sign_relay_request(&request, vector.secret.as_bytes()).unwrap(),
        vector.signature
    );
}
