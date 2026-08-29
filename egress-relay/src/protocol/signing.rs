use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const HEADER_NAME: fn(char) -> bool =
    |character| character.is_ascii_alphanumeric() || character == '-';

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    UnsupportedVersion(u8),
    InvalidField(&'static str),
    DuplicateHeader(String),
    InvalidHeaderName(String),
    InvalidHeaderValue,
    InvalidBase64Url,
    InvalidSecret,
}

#[derive(Debug)]
pub struct RelaySigningInput<'a> {
    pub version: u8,
    pub key_id: &'a str,
    pub timestamp: i64,
    pub nonce: &'a str,
    pub method: &'a str,
    pub target: &'a str,
    pub headers: &'a [[String; 2]],
    pub body: &'a [u8],
}

fn normalize_header_name(raw_name: &str) -> Result<String, ProtocolError> {
    let name = raw_name.to_ascii_lowercase();
    if name.is_empty()
        || !name.chars().all(HEADER_NAME)
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        return Err(ProtocolError::InvalidHeaderName(raw_name.to_owned()));
    }
    Ok(name)
}

pub fn normalize_header_value(value: &str) -> Result<String, ProtocolError> {
    if value.contains(['\r', '\n']) {
        return Err(ProtocolError::InvalidHeaderValue);
    }

    let mut normalized = String::new();
    let mut pending_whitespace = false;
    for character in value.chars() {
        if character == ' ' || character == '\t' {
            if !normalized.is_empty() {
                pending_whitespace = true;
            }
            continue;
        }
        if pending_whitespace {
            normalized.push(' ');
            pending_whitespace = false;
        }
        normalized.push(character);
    }
    Ok(normalized)
}

pub fn canonicalize_headers(headers: &[[String; 2]]) -> Result<String, ProtocolError> {
    let mut normalized = Vec::with_capacity(headers.len());
    for [raw_name, raw_value] in headers {
        normalized.push((
            normalize_header_name(raw_name)?,
            normalize_header_value(raw_value)?,
        ));
    }

    normalized.sort_by(|left, right| left.0.cmp(&right.0));
    for pair in normalized.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(ProtocolError::DuplicateHeader(pair[0].0.clone()));
        }
    }

    let mut result = String::new();
    for (name, value) in normalized {
        result.push_str(&name);
        result.push(':');
        result.push_str(&value);
        result.push('\n');
    }
    Ok(result)
}

pub fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn base64url_decode(value: &str) -> Result<Vec<u8>, ProtocolError> {
    if value.contains('=') || value.len() % 4 == 1 {
        return Err(ProtocolError::InvalidBase64Url);
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
    {
        return Err(ProtocolError::InvalidBase64Url);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProtocolError::InvalidBase64Url)
}

pub fn sha256_base64url(body: &[u8]) -> String {
    base64url_encode(&Sha256::digest(body))
}

fn reject_line_breaks(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.contains(['\r', '\n']) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ProtocolError> {
    let decoded = base64url_decode(value)?;
    if decoded.len() != 32 {
        return Err(ProtocolError::InvalidField("body_sha256"));
    }
    Ok(())
}

pub fn build_canonical_request(input: &RelaySigningInput<'_>) -> Result<String, ProtocolError> {
    if input.version != 1 {
        return Err(ProtocolError::UnsupportedVersion(input.version));
    }
    if input.timestamp < 0 {
        return Err(ProtocolError::InvalidField("timestamp"));
    }
    if input.key_id.is_empty() {
        return Err(ProtocolError::InvalidField("key_id"));
    }
    reject_line_breaks("key_id", input.key_id)?;
    reject_line_breaks("nonce", input.nonce)?;
    reject_line_breaks("target", input.target)?;

    let nonce = base64url_decode(input.nonce)?;
    if nonce.len() != 16 {
        return Err(ProtocolError::InvalidField("nonce"));
    }

    let method = input.method.to_ascii_uppercase();
    if method.is_empty()
        || !method
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidField("method"));
    }

    let body_sha256 = sha256_base64url(input.body);
    validate_digest(&body_sha256)?;
    let canonical_headers = canonicalize_headers(input.headers)?;

    Ok([
        "codex-relay-v1".to_owned(),
        input.key_id.to_owned(),
        input.timestamp.to_string(),
        input.nonce.to_owned(),
        method,
        base64url_encode(input.target.as_bytes()),
        body_sha256,
        base64url_encode(canonical_headers.as_bytes()),
    ]
    .join("\n"))
}

pub fn sign_relay_request(
    input: &RelaySigningInput<'_>,
    secret: &[u8],
) -> Result<String, ProtocolError> {
    if secret.is_empty() {
        return Err(ProtocolError::InvalidSecret);
    }
    let canonical = build_canonical_request(input)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| ProtocolError::InvalidSecret)?;
    mac.update(canonical.as_bytes());
    Ok(base64url_encode(&mac.finalize().into_bytes()))
}
