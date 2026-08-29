import { describe, expect, it } from "vitest";
import fixtureV1 from "./fixtures/relay-protocol-v1.json";
import fixtureV2 from "./fixtures/relay-protocol-v2.json";
import {
  base64UrlDecode,
  base64UrlEncode,
  buildCanonicalRequest,
  canonicalizeHeaders,
  CURRENT_VERSION,
  DOMAIN_SEPARATOR_V1,
  DOMAIN_SEPARATOR_V2,
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

/**
 * Both live generations, each against its own frozen fixture.
 *
 * The relay and this Worker deploy independently, so a v1 relay can be serving
 * this Worker mid-rollout. v1 signing therefore stays a tested contract, not
 * history: if it were dropped here, a v1 regression would only surface as
 * authentication failures against a relay that has not been upgraded yet.
 */
const GENERATIONS: Array<[string, Fixture]> = [
  ["v1", fixtureV1 as Fixture],
  ["v2", fixtureV2 as Fixture],
];

/** The generation this Worker actually sends, for generation-agnostic checks. */
const vector = fixtureV2 as Fixture;

function inputFor(fixture: Fixture, body = new TextEncoder().encode(fixture.body_utf8)) {
  return {
    version: fixture.version,
    keyId: fixture.key_id,
    timestamp: fixture.timestamp,
    nonce: fixture.nonce,
    method: fixture.method,
    target: fixture.target,
    headers: fixture.headers,
    body,
  };
}

function input(body = new TextEncoder().encode(vector.body_utf8)) {
  return inputFor(vector, body);
}

describe.each(GENERATIONS)("relay protocol %s", (label, fixture) => {
  it("matches the shared canonical request and HMAC fixture", async () => {
    const request = inputFor(fixture);

    expect(fixture.version, `${label} fixture must declare its own version`).toBe(
      label === "v1" ? 1 : 2,
    );
    expect(canonicalizeHeaders(request.headers)).toBe(fixture.canonical_header_block);
    expect(base64UrlEncode(new TextEncoder().encode(fixture.target))).toBe(fixture.target_b64);
    expect(base64UrlEncode(new TextEncoder().encode(fixture.canonical_header_block))).toBe(
      fixture.canonical_header_block_b64,
    );
    expect(await sha256Base64Url(request.body)).toBe(fixture.body_sha256);
    expect(buildCanonicalRequest(request, fixture.body_sha256)).toBe(fixture.canonical_request);
    expect(await signRelayRequest(request, fixture.secret)).toBe(fixture.signature);
  });
});

describe("relay protocol generations", () => {
  // The separator is line 1 of the canonical request, so it is the whole of the
  // difference between generations. Asserting the rest is identical is what
  // proves the migration renamed a domain rather than reshaping the protocol --
  // a reshaped field would still produce two distinct signatures and look fine.
  it("differs only on the signing domain", () => {
    const v1 = buildCanonicalRequest(inputFor(fixtureV1 as Fixture), fixtureV1.body_sha256);
    const v2 = buildCanonicalRequest(inputFor(fixtureV2 as Fixture), fixtureV2.body_sha256);

    const [firstV1, ...restV1] = v1.split("\n");
    const [firstV2, ...restV2] = v2.split("\n");

    expect(firstV1).toBe(DOMAIN_SEPARATOR_V1);
    expect(firstV2).toBe(DOMAIN_SEPARATOR_V2);
    expect(restV2).toEqual(restV1);
  });

  // Same bytes under a different domain must not verify. Without this, a relay
  // could accept a v1 signature as v2 and the rename would be cosmetic rather
  // than a real domain separation.
  it("produces a different signature per generation for identical inputs", async () => {
    const v1 = await signRelayRequest(inputFor(fixtureV1 as Fixture), fixtureV1.secret);
    const v2 = await signRelayRequest(inputFor(fixtureV2 as Fixture), fixtureV2.secret);

    expect(fixtureV1.secret).toBe(fixtureV2.secret);
    expect(v2).not.toBe(v1);
  });

  it("sends the current generation", () => {
    expect(CURRENT_VERSION).toBe(2);
  });

  // An unknown version must be refused, never silently signed under the newest
  // domain: a future v3 signed as v2 would verify against the wrong domain and
  // the mistake would only appear as an authentication failure.
  it("rejects unknown protocol versions", () => {
    expect(() => buildCanonicalRequest({ ...input(), version: 3 }, vector.body_sha256)).toThrowError(
      expect.objectContaining({ code: "unsupported_version" }),
    );
    expect(() => buildCanonicalRequest({ ...input(), version: 0 }, vector.body_sha256)).toThrowError(
      expect.objectContaining({ code: "unsupported_version" }),
    );
  });
});

describe("relay canonicalization", () => {
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
