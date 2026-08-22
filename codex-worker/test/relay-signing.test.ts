import { describe, expect, it } from "vitest";
import fixture from "./fixtures/relay-protocol-v1.json";
import {
  base64UrlDecode,
  base64UrlEncode,
  buildCanonicalRequest,
  canonicalizeHeaders,
  ProtocolError,
} from "../src/relay/protocol";
import { signRelayRequest, sha256Base64Url } from "../src/relay/signing";

type Fixture = {
  version: number;
  key_id: string;
  timestamp: number;
  nonce: string;
  method: string;
  target: string;
  headers: Array<[string, string]>;
  body_utf8: string;
  canonical_header_block: string;
  canonical_header_block_b64: string;
  target_b64: string;
  body_sha256: string;
  canonical_request: string;
  secret: string;
  signature: string;
};

const vector = fixture as Fixture;

function input(body = new TextEncoder().encode(vector.body_utf8)) {
  return {
    version: vector.version,
    keyId: vector.key_id,
    timestamp: vector.timestamp,
    nonce: vector.nonce,
    method: vector.method,
    target: vector.target,
    headers: vector.headers,
    body,
  };
}

describe("relay protocol v1", () => {
  it("matches the shared canonical request and HMAC fixture", async () => {
    const request = input();

    expect(canonicalizeHeaders(request.headers)).toBe(vector.canonical_header_block);
    expect(base64UrlEncode(new TextEncoder().encode(vector.target))).toBe(vector.target_b64);
    expect(base64UrlEncode(new TextEncoder().encode(vector.canonical_header_block))).toBe(
      vector.canonical_header_block_b64,
    );
    expect(await sha256Base64Url(request.body)).toBe(vector.body_sha256);
    expect(buildCanonicalRequest(request, vector.body_sha256)).toBe(vector.canonical_request);
    expect(await signRelayRequest(request, vector.secret)).toBe(vector.signature);
  });

  it("rejects unknown protocol versions", () => {
    expect(() => buildCanonicalRequest({ ...input(), version: 2 }, vector.body_sha256)).toThrowError(
      expect.objectContaining({ code: "unsupported_version" }),
    );
  });

  it("rejects duplicate canonical header names", () => {
    expect(() => canonicalizeHeaders([["X-Test", "one"], ["x-test", "two"]])).toThrowError(
      expect.objectContaining({ code: "duplicate_header" }),
    );
  });

  it("rejects illegal header names and CR/LF in values", () => {
    expect(() => canonicalizeHeaders([["X Bad", "value"]])).toThrowError(ProtocolError);
    expect(() => canonicalizeHeaders([["x-test", "ok\r\nforged: yes"]])).toThrowError(
      expect.objectContaining({ code: "invalid_header_value" }),
    );
  });

  it("normalizes header whitespace without changing the signed name", () => {
    expect(canonicalizeHeaders([["X-Test", " \talpha\t  beta   gamma \t"]])).toBe(
      "x-test:alpha beta gamma\n",
    );
  });

  it("rejects padded or malformed base64url", () => {
    expect(() => base64UrlDecode(`${vector.signature}=`)).toThrowError(
      expect.objectContaining({ code: "invalid_base64url" }),
    );
    expect(() => base64UrlDecode("a")).toThrowError(
      expect.objectContaining({ code: "invalid_base64url" }),
    );
    expect(() => base64UrlDecode("not+base64")).toThrowError(
      expect.objectContaining({ code: "invalid_base64url" }),
    );
  });

  it("changes the body digest and signature when one body byte changes", async () => {
    const body = new TextEncoder().encode(vector.body_utf8);
    const changed = new Uint8Array(body);
    changed[changed.length - 1] ^= 1;

    expect(await sha256Base64Url(changed)).not.toBe(vector.body_sha256);
    expect(await signRelayRequest(input(changed), vector.secret)).not.toBe(vector.signature);
  });

  it("signs non-ASCII targets after UTF-8 percent encoding", async () => {
    const request = {
      ...input(new Uint8Array()),
      target: "https://例え.テスト/v1/路径?q=雪",
    };
    const canonical = buildCanonicalRequest(request, vector.body_sha256);

    expect(canonical.split("\n")[5]).toBe(
      "aHR0cHM6Ly_kvovjgYgu44OG44K544OIL3YxL-i3r-W-hD9xPembqg",
    );
    expect(await signRelayRequest(request, vector.secret)).not.toBe(vector.signature);
  });
});
