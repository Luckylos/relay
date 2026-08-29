export type ProtocolErrorCode =
  | "unsupported_version"
  | "invalid_field"
  | "duplicate_header"
  | "invalid_header_name"
  | "invalid_header_value"
  | "invalid_base64url";

export class ProtocolError extends Error {
  readonly code: ProtocolErrorCode;

  constructor(code: ProtocolErrorCode, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

export interface RelaySigningInput {
  version: number;
  keyId: string;
  timestamp: number;
  nonce: string;
  method: string;
  target: string;
  headers: ReadonlyArray<readonly [string, string]>;
  body: Uint8Array;
}

const HEADER_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;
const textEncoder = new TextEncoder();

/**
 * Signing-domain separator, one constant per protocol generation.
 *
 * This token is line 1 of every canonical request, so it is the one part of the
 * wire contract that cannot be renamed in place: editing it changes every
 * signature this build produces. It is therefore *versioned* rather than
 * renamed -- v1 keeps its original token forever, so a relay still verifying v1
 * accepts requests from an ingress that has not been redeployed yet.
 */
export const DOMAIN_SEPARATOR_V1 = "codex-relay-v1";

/**
 * v2 renames the project's own token. The `codex-` prefix predates this relay
 * serving the Claude ingress as well, so it described where the code came from
 * rather than what signs with it.
 */
export const DOMAIN_SEPARATOR_V2 = "egress-relay-v2";

/** Highest generation this build emits. Verification still accepts v1. */
export const CURRENT_VERSION = 2;

/**
 * Map a protocol generation to the domain separator it signs under.
 *
 * Rejecting an unknown version here (rather than defaulting) is what keeps a
 * future v3 from being silently signed under v2's domain.
 */
function domainSeparator(version: number): string {
  switch (version) {
    case 1:
      return DOMAIN_SEPARATOR_V1;
    case 2:
      return DOMAIN_SEPARATOR_V2;
    default:
      throw new ProtocolError(
        "unsupported_version",
        `unsupported relay protocol version: ${version}`,
      );
  }
}

function invalidField(field: string): never {
  throw new ProtocolError("invalid_field", `invalid relay field: ${field}`);
}

function rejectLineBreaks(field: string, value: string): void {
  if (/[\r\n]/.test(value)) {
    invalidField(field);
  }
}

export function normalizeHeaderValue(value: string): string {
  if (/[\r\n]/.test(value)) {
    throw new ProtocolError("invalid_header_value", "header value contains CR/LF");
  }

  let normalized = "";
  let pendingWhitespace = false;
  for (const character of value) {
    if (character === " " || character === "\t") {
      if (normalized.length > 0) {
        pendingWhitespace = true;
      }
      continue;
    }
    if (pendingWhitespace) {
      normalized += " ";
      pendingWhitespace = false;
    }
    normalized += character;
  }
  return normalized;
}

export function canonicalizeHeaders(
  headers: ReadonlyArray<readonly [string, string]>,
): string {
  const normalized = headers.map(([rawName, rawValue]) => {
    const name = rawName.toLowerCase();
    if (!HEADER_NAME.test(name)) {
      throw new ProtocolError("invalid_header_name", `invalid header name: ${rawName}`);
    }
    return [name, normalizeHeaderValue(rawValue)] as const;
  });

  // Spec §5.2 requires ASCII ascending order. localeCompare() is
  // locale-dependent collation and would silently disagree with the Rust
  // relay's byte ordering on some hosts, breaking HMAC verification.
  normalized.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1]?.[0] === normalized[index]?.[0]) {
      throw new ProtocolError(
        "duplicate_header",
        `duplicate canonical header: ${normalized[index]?.[0]}`,
      );
    }
  }

  return normalized.map(([name, value]) => `${name}:${value}\n`).join("");
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(value: string): Uint8Array {
  if (!BASE64URL.test(value) || value.length % 4 === 1) {
    throw new ProtocolError("invalid_base64url", "invalid unpadded base64url");
  }

  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    throw new ProtocolError("invalid_base64url", "invalid unpadded base64url");
  }

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function validateDigest(field: string, value: string): void {
  const decoded = base64UrlDecode(value);
  if (decoded.length !== 32) {
    invalidField(field);
  }
}

export function buildCanonicalRequest(input: RelaySigningInput, bodySha256: string): string {
  // Resolved before any other validation so an unsupported generation is
  // reported as such rather than as whichever field happens to fail first.
  const separator = domainSeparator(input.version);
  if (!Number.isSafeInteger(input.timestamp) || input.timestamp < 0) {
    invalidField("timestamp");
  }
  if (input.keyId.length === 0) {
    invalidField("key_id");
  }
  rejectLineBreaks("key_id", input.keyId);
  rejectLineBreaks("nonce", input.nonce);
  rejectLineBreaks("target", input.target);
  const nonce = base64UrlDecode(input.nonce);
  if (nonce.length !== 16) {
    invalidField("nonce");
  }
  const method = input.method.toUpperCase();
  if (!/^[A-Z]+$/.test(method)) {
    invalidField("method");
  }
  validateDigest("body_sha256", bodySha256);

  const canonicalHeaders = canonicalizeHeaders(input.headers);
  const encodedTarget = base64UrlEncode(textEncoder.encode(input.target));
  const encodedHeaders = base64UrlEncode(textEncoder.encode(canonicalHeaders));
  return [
    separator,
    input.keyId,
    String(input.timestamp),
    input.nonce,
    method,
    encodedTarget,
    bodySha256,
    encodedHeaders,
  ].join("\n");
}

export function utf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}
