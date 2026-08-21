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
    // A real relay stamps attribution on every reply, so the stub must too:
    // without it the response is (correctly) read as a relay failure.
    const upstream = new Response("upstream-body", {
      status: 201,
      headers: {
        "content-type": "text/plain",
        "x-codex-relay-result": "upstream",
        "x-codex-relay-request-id": "fixture-id",
      },
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
  /** 43 base64url chars = 32 random bytes, the production minimum. */
  const TOKEN = "Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OTBhYmNkZWZnaGk";
  const AUTH = { "x-codex-relay-token": TOKEN } as const;
  const env = {
    INGRESS_AUTH_TOKEN: TOKEN,
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
          headers: AUTH,
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
          headers: AUTH,
          body: "payload",
        }),
        // Ingress token present but relay unconfigured: this must exercise the
        // relay fail-closed path, not the ingress gate.
        { INGRESS_AUTH_TOKEN: TOKEN } as never,
        {} as ExecutionContext,
      );
      expect(response.status).toBe(502);
    } finally {
      globalThis.fetch = original;
    }

    expect(calls, "unconfigured relay must not reach any upstream").toBe(0);
  });
});

describe("relay error attribution", () => {
  // A relay-generated reply, as the relay now stamps it.
  function relayError(status: number, machineCode: string): Response {
    return new Response(
      JSON.stringify({ error: { type: machineCode, message: "relay request rejected" } }),
      {
        status,
        headers: {
          "content-type": "application/json",
          "x-codex-relay-result": "error",
          "x-codex-relay-error": machineCode,
          "x-codex-relay-request-id": "abc123",
        },
      },
    );
  }

  function send(upstream: Response): Promise<Response> {
    return sendViaRelay({
      relayUrl: RELAY_URL,
      keyId: KEY_ID,
      secret: SECRET,
      target: targetFor("/https/api.openai.com/v1/responses"),
      method: "POST",
      headers: new Headers({ authorization: "Bearer token" }),
      body: new TextEncoder().encode("payload"),
      fetchImpl: async () => upstream,
    });
  }

  // Passing the relay's own status through tells the client something false about
  // the upstream and leaks the relay's auth verdict: a 401 reads as "your API key
  // is bad", a 409 as an upstream conflict, a 413 as an upstream size limit. All
  // three are the relay talking about itself.
  it.each([
    [401, "relay_auth_error"],
    [409, "relay_replay"],
    [413, "relay_body_too_large"],
    [400, "relay_protocol_error"],
    [500, "relay_internal_error"],
  ])("maps relay-generated %i %s to 502 relay_unavailable", async (status, code) => {
    const response = await send(relayError(status, code));

    expect(response.status, `relay ${status} must not reach the client`).toBe(502);
    const body = (await response.json()) as { error: { type: string; message: string } };
    expect(body.error.type).toBe("relay_unavailable");
    // The machine code names an internal gate; echoing it tells an attacker
    // which check they tripped.
    expect(JSON.stringify(body)).not.toContain(code);
  });

  it("maps relay upstream_timeout to 504 and upstream_error to 502", async () => {
    const timeout = await send(relayError(504, "relay_upstream_timeout"));
    expect(timeout.status).toBe(504);
    expect(((await timeout.json()) as { error: { type: string } }).error.type).toBe(
      "upstream_timeout",
    );

    const failed = await send(relayError(502, "relay_upstream_error"));
    expect(failed.status).toBe(502);
    expect(((await failed.json()) as { error: { type: string } }).error.type).toBe(
      "upstream_error",
    );
  });

  // Forward-looking: the relay does not emit `relay_busy` yet, because the
  // concurrency cap (spec section 8 / CODEX_RELAY_MAX_CONCURRENCY) is not
  // implemented. The mapping is asserted now so that whoever adds admission
  // control finds the client-facing contract already pinned, rather than
  // discovering saturation collapses into an opaque 502.
  it("maps relay saturation to 503 relay_busy", async () => {
    const busy = await send(relayError(503, "relay_busy"));
    expect(busy.status).toBe(503);
    expect(((await busy.json()) as { error: { type: string } }).error.type).toBe("relay_busy");
  });

  // The mirror image: an upstream 4xx/5xx is real information the client needs.
  // Rewriting it into a relay error would hide genuine API errors.
  it.each([400, 401, 404, 429, 500, 502, 503])(
    "returns a genuine upstream %i verbatim",
    async (status) => {
      const upstream = new Response(JSON.stringify({ error: { message: "from upstream" } }), {
        status,
        headers: {
          "content-type": "application/json",
          "x-codex-relay-result": "upstream",
          "x-codex-relay-request-id": "abc123",
        },
      });

      const response = await send(upstream);

      expect(response.status, "an upstream status belongs to the upstream").toBe(status);
      const body = (await response.json()) as { error: { message: string } };
      expect(body.error.message).toBe("from upstream");
    },
  );

  // Control headers are an internal Worker<->relay channel. Leaking them tells a
  // client the relay exists, and hands it a correlation id it has no use for.
  it("never leaks relay control headers to the client", async () => {
    for (const upstream of [
      relayError(401, "relay_auth_error"),
      new Response("ok", {
        status: 200,
        headers: {
          "x-codex-relay-result": "upstream",
          "x-codex-relay-request-id": "abc123",
        },
      }),
    ]) {
      const response = await send(upstream);
      for (const [name] of response.headers) {
        expect(name.toLowerCase(), `${name} must not reach the client`).not.toMatch(
          /^x-codex-relay-/,
        );
      }
    }
  });

  // Absent attribution means an unknown or pre-upgrade relay. Treating that as
  // "upstream" would pass a relay 401 straight through, which is the exact bug
  // the header exists to prevent, so the safe reading is "relay error".
  it("treats a missing result header as a relay error", async () => {
    const response = await send(
      new Response(JSON.stringify({ error: { type: "relay_auth_error" } }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    );

    expect(response.status).toBe(502);
    expect(((await response.json()) as { error: { type: string } }).error.type).toBe(
      "relay_unavailable",
    );
  });
});
