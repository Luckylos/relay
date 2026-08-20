import { describe, expect, it } from "vitest";

import { sendViaRelay } from "../src/relay/client";
import { canonicalizeHeaders, base64UrlDecode } from "../src/relay/protocol";
import { signRelayRequest } from "../src/relay/signing";
import { parseTarget } from "../src/target";
import worker from "../src/index";

const SECRET = "relay-test-secret";
const KEY_ID = "key-1";
const RELAY_URL = "https://relay.example.com/v1/forward";

function targetFor(path: string): ReturnType<typeof parseTarget> {
  return parseTarget(new Request(`https://worker.example.com${path}`));
}

function decodeUtf8(value: string): string {
  return new TextDecoder().decode(base64UrlDecode(value));
}

describe("relay client wire protocol", () => {
  it("sends the signed relay envelope to the fixed relay endpoint", async () => {
    let seen: Request | undefined;
    const upstream = new Response("upstream-body", {
      status: 201,
      headers: { "content-type": "text/plain" },
    });

    const response = await sendViaRelay({
      relayUrl: RELAY_URL,
      keyId: KEY_ID,
      secret: SECRET,
      target: targetFor("/api.openai.com/v1/responses?stream=true"),
      method: "POST",
      headers: new Headers({ authorization: "Bearer token", "x-request-id": "fixture" }),
      body: new TextEncoder().encode("payload"),
      fetchImpl: async (request) => {
        seen = request as Request;
        return upstream;
      },
    });

    const sent = seen as Request;
    expect(sent.url).toBe(RELAY_URL);
    expect(sent.method).toBe("POST");

    // The business method and target travel as control headers, never as the
    // relay request's own method or path.
    expect(sent.headers.get("x-codex-relay-version")).toBe("1");
    expect(sent.headers.get("x-codex-relay-key-id")).toBe(KEY_ID);
    expect(sent.headers.get("x-codex-relay-method")).toBe("POST");
    expect(decodeUtf8(sent.headers.get("x-codex-relay-target") ?? "")).toBe(
      "https://api.openai.com/v1/responses?stream=true",
    );

    // Business headers move as a canonical block, so the relay can verify the
    // exact bytes that were signed.
    const block = decodeUtf8(sent.headers.get("x-codex-relay-headers") ?? "");
    expect(block).toBe(
      canonicalizeHeaders([
        ["authorization", "Bearer token"],
        ["x-request-id", "fixture"],
      ]),
    );

    // Body is relayed verbatim and covered by the digest.
    expect(new Uint8Array(await sent.arrayBuffer())).toEqual(
      new TextEncoder().encode("payload"),
    );

    const timestamp = Number(sent.headers.get("x-codex-relay-timestamp"));
    expect(Number.isSafeInteger(timestamp)).toBe(true);

    const expected = await signRelayRequest(
      {
        version: 1,
        keyId: KEY_ID,
        timestamp,
        nonce: sent.headers.get("x-codex-relay-nonce") ?? "",
        method: "POST",
        target: "https://api.openai.com/v1/responses?stream=true",
        headers: [
          ["authorization", "Bearer token"],
          ["x-request-id", "fixture"],
        ],
        body: new TextEncoder().encode("payload"),
      },
      SECRET,
    );
    expect(sent.headers.get("x-codex-relay-signature")).toBe(expected);

    expect(response.status).toBe(201);
    expect(await response.text()).toBe("upstream-body");
  });
});

describe("worker relay fail-closed routing", () => {
  const env = {
    EGRESS_RELAY_URL: RELAY_URL,
    EGRESS_RELAY_KEY_ID: KEY_ID,
    EGRESS_RELAY_SECRET: SECRET,
  };

  it("refuses to serve a request when the relay is not configured", async () => {
    // The whole point of the relay is that egress leaves the VPS IP. A missing
    // relay config must fail the request, never silently fall back to the
    // Worker's own Cloudflare egress.
    for (const missing of ["EGRESS_RELAY_URL", "EGRESS_RELAY_KEY_ID", "EGRESS_RELAY_SECRET"]) {
      const partial: Record<string, string> = { ...env };
      delete partial[missing];

      const response = await worker.fetch(
        new Request("https://worker.example.com/api.openai.com/v1/responses", {
          method: "POST",
          body: "payload",
        }),
        partial as never,
        {} as ExecutionContext,
      );

      expect(response.status, `missing ${missing} must fail closed`).toBe(502);
      const payload = (await response.json()) as { error: { type: string } };
      expect(payload.error.type).toBe("relay_unavailable");
    }
  });

  it("does not touch the network when the relay is not configured", async () => {
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      return new Response("must-not-happen");
    }) as typeof fetch;

    try {
      const response = await worker.fetch(
        new Request("https://worker.example.com/api.openai.com/v1/responses", {
          method: "POST",
          body: "payload",
        }),
        {} as never,
        {} as ExecutionContext,
      );
      expect(response.status).toBe(502);
    } finally {
      globalThis.fetch = original;
    }

    expect(calls, "unconfigured relay must not reach any upstream").toBe(0);
  });
});
