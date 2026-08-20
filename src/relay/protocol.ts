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

  normalized.sort(([left], [right]) => left.localeCompare(right));
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
  if (input.version !== 1) {
    throw new ProtocolError("unsupported_version", `unsupported relay protocol version: ${input.version}`);
  }
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
    "codex-relay-v1",
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
