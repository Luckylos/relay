import { describe, expect, it, vi } from "vitest";

import { sendViaRelay } from "../src/relay/client";
import {
  CURRENT_VERSION,
  canonicalizeHeaders,
  base64UrlDecode,
} from "../src/relay/protocol";
import { signRelayRequest } from "../src/relay/signing";
import { parseTarget } from "../src/target";
import { asUpstream } from "./support/relay-stub";
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
    const upstream = asUpstream(
      new Response("upstream-body", {
        status: 201,
        headers: { "content-type": "text/plain" },
      }),
    );

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
    //
    // Asserted in the current namespace only. The Worker sends exactly one
    // generation, and pinning which one is the point: a dual read here would let
    // a regression that emitted the legacy names keep passing.
    expect(sent.headers.get("x-egress-relay-version")).toBe(String(CURRENT_VERSION));
    expect(sent.headers.get("x-egress-relay-key-id")).toBe(KEY_ID);
    expect(sent.headers.get("x-egress-relay-method")).toBe("POST");
    expect(decodeUtf8(sent.headers.get("x-egress-relay-target") ?? "")).toBe(
      "https://api.openai.com/v1/responses?stream=true",
    );

    // A mixed envelope is refused by the relay as `relay_duplicate_control`, so
    // emitting both generations at once would be an outage, not compatibility.
    for (const [name] of sent.headers) {
      expect(name.toLowerCase(), `${name} is a stale envelope name`).not.toMatch(
        /^x-codex-relay-/,
      );
    }

    // Business headers move as a canonical block, so the relay can verify the
    // exact bytes that were signed.
    const block = decodeUtf8(sent.headers.get("x-egress-relay-headers") ?? "");
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

    const timestamp = Number(sent.headers.get("x-egress-relay-timestamp"));
    expect(Number.isSafeInteger(timestamp)).toBe(true);

    // Signed under the same generation the envelope names declare. A relay picks
    // the verifying domain from those names, so a signature produced under a
    // different generation fails as a bad signature -- an authentication error
    // whose real cause is a half-finished rename.
    const expected = await signRelayRequest(
      {
        version: CURRENT_VERSION,
        keyId: KEY_ID,
        timestamp,
        nonce: sent.headers.get("x-egress-relay-nonce") ?? "",
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
    expect(sent.headers.get("x-egress-relay-signature")).toBe(expected);

    expect(response.status).toBe(201);
    expect(await response.text()).toBe("upstream-body");
  });
});

describe("worker relay fail-closed routing", () => {
  /** 43 base64url chars = 32 random bytes, the production minimum. */
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
        // Ingress token present but relay unconfigured: this must exercise the
        // relay fail-closed path, not the ingress gate.
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

/**
 * Attribution is read from whichever namespace the relay answered in.
 *
 * The relay and this Worker deploy independently, so all three shapes are live
 * across the migration: an upgraded relay stamps both generations, one that has
 * not been upgraded stamps only the legacy names, and a post-window relay stamps
 * only the current ones. Testing a single shape would let a one-namespace read
 * pass here while turning the other relay into a total outage -- every request
 * failing closed to `502 relay_unavailable` with nothing actually broken.
 */
describe.each([
  ["current-only", ["x-egress-relay-"]],
  ["legacy-only", ["x-codex-relay-"]],
  ["dual-stamping", ["x-egress-relay-", "x-codex-relay-"]],
] as const)("relay error attribution from a %s relay", (_shape, prefixes) => {
  /** The same control fields, named in whichever generations this relay stamps. */
  function control(fields: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const prefix of prefixes) {
      for (const [field, value] of Object.entries(fields)) {
        headers[`${prefix}${field}`] = value;
      }
    }
    return headers;
  }

  // A relay-generated reply, as the relay stamps it.
  function relayError(status: number, machineCode: string): Response {
    return new Response(
      JSON.stringify({ error: { type: machineCode, message: "relay request rejected" } }),
      {
        status,
        headers: {
          "content-type": "application/json",
          ...control({ result: "error", error: machineCode, "request-id": "abc123" }),
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

  it("logs relay attribution metadata without logging the relay body", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const response = await send(
        new Response("sensitive relay response body", {
          status: 401,
          headers: {
            "cf-ray": "ray123-SIN",
            ...control({
              result: "error",
              error: "relay_auth_error",
              "request-id": "relay-request-123",
            }),
          },
        }),
      );

      expect(response.status).toBe(502);
      expect(log).toHaveBeenCalledExactlyOnceWith(
        JSON.stringify({
          event: "relay_attribution_failure",
          relay_status: 401,
          relay_result: "error",
          relay_error: "relay_auth_error",
          relay_request_id: "relay-request-123",
          cf_ray: "ray123-SIN",
        }),
      );
      expect(log.mock.calls[0]?.[0]).not.toContain("sensitive relay response body");
    } finally {
      log.mockRestore();
    }
  });

  it("logs missing relay attribution headers as null", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const response = await send(
        new Response("edge error body", {
          status: 502,
          headers: { "cf-ray": "edge456-SIN" },
        }),
      );

      expect(response.status).toBe(502);
      expect(log).toHaveBeenCalledExactlyOnceWith(
        JSON.stringify({
          event: "relay_attribution_failure",
          relay_status: 502,
          relay_result: null,
          relay_error: null,
          relay_request_id: null,
          cf_ray: "edge456-SIN",
        }),
      );
      expect(log.mock.calls[0]?.[0]).not.toContain("edge error body");
    } finally {
      log.mockRestore();
    }
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
          ...control({ result: "upstream", "request-id": "abc123" }),
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
        headers: control({ result: "upstream", "request-id": "abc123" }),
      }),
    ]) {
      const response = await send(upstream);
      for (const [name] of response.headers) {
        // Both namespaces, not just the one this relay stamped: the strip is by
        // prefix, and a leak of either generation tells the client a relay exists
        // and hands it a correlation id it has no use for.
        expect(name.toLowerCase(), `${name} must not reach the client`).not.toMatch(
          /^x-(egress|codex)-relay-/,
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
