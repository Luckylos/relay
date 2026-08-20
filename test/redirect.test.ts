import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";
import { base64UrlDecode } from "../src/relay/protocol";
import { RedirectError, rewriteLocation } from "../src/redirect";
import { parseTarget } from "../src/target";

const WORKER_ORIGIN = "https://worker.example";

/** 43 base64url chars = 32 random bytes, the production minimum. */
const TOKEN = "Zm9vYmFyYmF6cXV1eDEyMzQ1Njc4OTBhYmNkZWZnaGk";
const AUTH = { "x-codex-relay-token": TOKEN } as const;

const ENV: Env = {
  INGRESS_AUTH_TOKEN: TOKEN,
  EGRESS_RELAY_URL: "https://relay.internal.example/v1/forward",
  EGRESS_RELAY_KEY_ID: "key-1",
  EGRESS_RELAY_SECRET: "relay-test-secret",
};

function context(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

function target(path: string) {
  return parseTarget(new Request(`${WORKER_ORIGIN}${path}`));
}

function rewrite(location: string, path = "/api.example.com/v1/responses") {
  return rewriteLocation(location, target(path), new URL(`${WORKER_ORIGIN}${path}`));
}

describe("upstream redirect rewriting", () => {
  it("keeps an absolute HTTPS redirect on the Worker origin", () => {
    // A client following this must come back through the Worker, not go straight
    // to the upstream host — otherwise egress leaves Cloudflare, not the VPS.
    expect(rewrite("https://other.example.com/v2/items?page=2")).toBe(
      "https://worker.example/other.example.com/v2/items?page=2",
    );
  });

  it("resolves a root-relative redirect against the original target", () => {
    expect(rewrite("/v2/items?page=2")).toBe(
      "https://worker.example/api.example.com/v2/items?page=2",
    );
  });

  it("resolves a path-relative redirect against the original target directory", () => {
    // RFC 3986 base resolution: /v1/responses -> /v1/ + next
    expect(rewrite("next?page=3")).toBe(
      "https://worker.example/api.example.com/v1/next?page=3",
    );
  });

  it("resolves a protocol-relative redirect as HTTPS", () => {
    expect(rewrite("//other.example.com/v2/items")).toBe(
      "https://worker.example/other.example.com/v2/items",
    );
  });

  it("preserves percent-encoding and query structure byte-for-byte", () => {
    const cases: Array<[string, string]> = [
      // An encoded slash must stay encoded: decoding it would change the target
      // path the upstream asked for.
      [
        "https://other.example.com/a%2Fb/c",
        "https://worker.example/other.example.com/a%2Fb/c",
      ],
      [
        "https://other.example.com/path%20with%20spaces",
        "https://worker.example/other.example.com/path%20with%20spaces",
      ],
      [
        "https://other.example.com/v1?q=a%26b&r=%3D",
        "https://worker.example/other.example.com/v1?q=a%26b&r=%3D",
      ],
      [
        "https://other.example.com/v1?empty=&flag",
        "https://worker.example/other.example.com/v1?empty=&flag",
      ],
    ];
    for (const [location, expected] of cases) {
      expect(rewrite(location), location).toBe(expected);
    }
  });

  it("drops the upstream fragment rather than forwarding it", () => {
    // Fragments are never sent to a server; keeping one would only be noise.
    expect(rewrite("https://other.example.com/v2#section")).toBe(
      "https://worker.example/other.example.com/v2",
    );
  });

  it("preserves a redirect back to the same host", () => {
    expect(rewrite("https://api.example.com/v1/responses/123")).toBe(
      "https://worker.example/api.example.com/v1/responses/123",
    );
  });

  it("accepts an explicit :443 because it is the default port", () => {
    // `URL` normalizes the default port away, so this is indistinguishable from
    // a portless redirect and carries no extra reach. Matches `parseTarget`,
    // which normalizes it the same way.
    expect(rewrite("https://other.example.com:443/v2")).toBe(
      "https://worker.example/other.example.com/v2",
    );
  });

  it("keeps the Worker origin's own port and scheme when it has one", () => {
    const path = "/api.example.com/v1/responses";
    expect(
      rewriteLocation(
        "https://other.example.com/v2",
        target(path),
        new URL(`https://worker.example:8787${path}`),
      ),
    ).toBe("https://worker.example:8787/other.example.com/v2");
  });

  it("rejects redirects that would escape the relay or the target contract", () => {
    // Each case asserts the reason, not just the error class. Several rules can
    // reject the same input, so a bare `toThrow(RedirectError)` would let an
    // individual rule be removed while a later one silently covers for it.
    const rejected: Array<[string, string, RegExp]> = [
      ["plaintext downgrade", "http://other.example.com/v2", /must be https/],
      ["userinfo", "https://user:pass@other.example.com/v2", /credentials/],
      ["userinfo without password", "https://user@other.example.com/v2", /credentials/],
      ["IPv4 literal", "https://203.0.113.9/v2", /not a valid target/],
      ["IPv6 literal", "https://[2001:db8::1]/v2", /not a valid target/],
      ["loopback name", "https://localhost/v2", /not a valid target/],
      ["non-HTTP scheme", "file:///etc/passwd", /must be https/],
      ["javascript scheme", "javascript:alert(1)", /must be https/],
      ["data scheme", "data:text/html,<b>x</b>", /must be https/],
      ["empty", "", /is empty/],
      ["whitespace only", "   ", /is empty/],
      ["underscore hostname", "https://bad_host.example/v2", /not a valid target/],
      ["trailing-dot-only hostname", "https://./v2", /not a valid target/],
      ["CR injection", "https://other.example.com/v2\r\nX-Injected: 1", /forbidden characters/],
      ["LF injection", "https://other.example.com/v2\nX-Injected: 1", /forbidden characters/],
      ["tab injection", "https://other.example.com/v2\tX", /forbidden characters/],
    ];

    for (const [label, location, reason] of rejected) {
      expect(() => rewrite(location), label).toThrow(RedirectError);
      expect(() => rewrite(location), label).toThrow(reason);
    }
  });

  it("rejects a hostname that would exceed the target contract length", () => {
    const tooLong = `${"a".repeat(64)}.example.com`;
    expect(() => rewrite(`https://${tooLong}/v2`)).toThrow(RedirectError);
  });

  it("names the port as the reason a ported redirect is refused", () => {
    // Distinguishes the port check from the round-trip self-check below it: both
    // raise RedirectError, so asserting only `toThrow` would let the dedicated
    // port rule be deleted without any test noticing.
    expect(() => rewrite("https://other.example.com:8443/v2")).toThrow(
      /must not specify a port/,
    );
  });

  it("emits a Location that parseTarget accepts back, byte-for-byte", () => {
    // The rewritten URL is only useful if it survives a round trip through the
    // inbound parser. Asserting the round trip pins the first path segment to a
    // bare hostname: a port-bearing `host` here would produce a target the Worker
    // could not parse on the next hop.
    const locations = [
      "https://other.example.com/v2/items?page=2",
      "https://other.example.com:443/v2",
      "/v2/items?page=2",
      "next?page=3",
      "//other.example.com/v2/items",
      "https://other.example.com/a%2Fb/c",
      "https://other.example.com/v1?q=a%26b&r=%3D",
    ];

    for (const location of locations) {
      const rewritten = rewrite(location);
      const reparsed = parseTarget(new Request(rewritten));
      // Round-tripping must reproduce the upstream URL the redirect pointed at.
      const expected = new URL(location, target("/api.example.com/v1/responses").url);
      expect(reparsed.url.toString(), location).toBe(
        `https://${expected.hostname}${expected.pathname}${expected.search}`,
      );
    }
  });
});

describe("Worker redirect handling end to end", () => {
  /** Stubs the relay so the upstream's 3xx is what the Worker actually sees. */
  function relayReturning(status: number, headers: Record<string, string>) {
    const fetchMock = vi.fn(async () => new Response("redirect body", { status, headers }));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("rewrites an upstream 302 onto the Worker origin and keeps status and body", async () => {
    const fetchMock = relayReturning(302, {
      location: "https://cdn.example.com/objects/42?token=abc",
      "x-upstream-note": "kept",
    });

    const response = await worker.fetch(
      new Request("https://worker.example/api.example.com/v1/responses", {
        method: "POST",
        headers: { ...AUTH, "content-type": "application/json" },
        body: "{}",
      }),
      ENV,
      context(),
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(response.status).toBe(302);
    // Rewritten to come back through the Worker, so the follow-up request is
    // relayed too instead of leaving Cloudflare directly.
    expect(response.headers.get("location")).toBe(
      "https://worker.example/cdn.example.com/objects/42?token=abc",
    );
    expect(response.headers.get("x-upstream-note")).toBe("kept");
    expect(await response.text()).toBe("redirect body");

    vi.unstubAllGlobals();
  });

  it("routes the rewritten Location back through the relay on the second hop", async () => {
    // Proves the rewrite is functional, not cosmetic: replaying it must produce
    // another relay call carrying the redirect's own target.
    const first = relayReturning(302, { location: "/v2/moved" });
    const initial = await worker.fetch(
      new Request("https://worker.example/api.example.com/v1/responses", {
        method: "GET",
        headers: AUTH,
      }),
      ENV,
      context(),
    );
    const location = initial.headers.get("location");
    expect(location).toBe("https://worker.example/api.example.com/v2/moved");
    expect(first).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();

    // Typed parameter so the recorded call exposes the relay Request it received.
    const second = vi.fn(async (_request: Request) => new Response("ok", { status: 200 }));
    vi.stubGlobal("fetch", second);
    const followed = await worker.fetch(
      new Request(location as string, { method: "GET", headers: AUTH }),
      ENV,
      context(),
    );

    expect(followed.status).toBe(200);
    expect(second).toHaveBeenCalledTimes(1);
    const relayRequest = second.mock.calls[0][0];
    expect(new URL(relayRequest.url).origin).toBe("https://relay.internal.example");
    // The target travels base64url-encoded, so decode before comparing.
    const relayTarget = new TextDecoder().decode(
      base64UrlDecode(relayRequest.headers.get("x-codex-relay-target") ?? ""),
    );
    expect(relayTarget).toBe("https://api.example.com/v2/moved");

    vi.unstubAllGlobals();
  });

  it("fails closed with 502 instead of leaking an off-relay Location", async () => {
    for (const location of [
      "http://cdn.example.com/plain",
      "https://169.254.169.254/latest/meta-data",
      "https://cdn.example.com:8443/objects/42",
    ]) {
      relayReturning(307, { location });

      const response = await worker.fetch(
        new Request("https://worker.example/api.example.com/v1/responses", {
          method: "GET",
          headers: AUTH,
        }),
        ENV,
        context(),
      );

      expect(response.status, location).toBe(502);
      expect(await response.json(), location).toEqual({
        error: {
          message: "invalid upstream redirect",
          type: "invalid_upstream_redirect",
        },
      });
      // The rejected Location must not survive anywhere in the client response.
      expect(response.headers.get("location"), location).toBeNull();

      vi.unstubAllGlobals();
    }
  });

  it("leaves non-redirect responses untouched", async () => {
    relayReturning(200, { "content-type": "application/json" });

    const response = await worker.fetch(
      new Request("https://worker.example/api.example.com/v1/responses", {
        method: "GET",
        headers: AUTH,
      }),
      ENV,
      context(),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();

    vi.unstubAllGlobals();
  });
});
