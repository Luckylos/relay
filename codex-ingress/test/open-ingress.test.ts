/**
 * Open ingress + upstream allowlist.
 *
 * This Worker has no client credential: anyone who points a base URL at it
 * works with no custom headers. That is the product requirement, so the tests
 * that matter are (a) an unadorned client really does get through, and (b) the
 * things that must NOT follow from being open — envelope forgery, and acting as
 * an open proxy to arbitrary hosts — still cannot happen.
 */
import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";
import { isAllowedUpstreamHost, parseTarget, TargetError } from "../src/target";
import { RedirectError, rewriteLocation } from "../src/redirect";
import { asUpstream } from "./support/relay-stub";
import { signedHeaders, signedTarget } from "./support/signed-block";

const ENV: Env = {
  CODEX_PROXY_INSTALLATION_ID: "11111111-1111-1111-1111-111111111111",
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

/**
 * Stub the relay, replying as a real one would.
 *
 * Reading the captured request out of `mock.calls` matches the convention in the
 * other suites and avoids the `Request` generic mismatch that a typed
 * `mockImplementation` parameter introduces.
 */
function captureRelay() {
  return vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(asUpstream(new Response('{"ok":true}', { status: 200 })));
}

function sentRequest(spy: ReturnType<typeof captureRelay>): Request {
  return spy.mock.calls[0]?.[0] as Request;
}

describe("open ingress", () => {
  it("relays a request that carries no Worker-specific header at all", async () => {
    // The whole point: a stock OpenAI-compatible client, configured with nothing
    // but a base URL and its own key, must work.
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        new Request("https://w.example/api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            authorization: "Bearer sk-caller-own-key",
            "content-type": "application/json",
          },
          body: '{"model":"gpt-5.6","input":"hi"}',
        }),
        ENV,
        context(),
      );

      expect(response.status).toBe(200);
      expect(spy).toHaveBeenCalledTimes(1);
      // The caller's own upstream credential is forwarded untouched.
      expect(signedHeaders(sentRequest(spy)).get("authorization")).toBe(
        "Bearer sk-caller-own-key",
      );
    } finally {
      spy.mockRestore();
    }
  });

  it("supplies Codex identity so the client never has to fake it", async () => {
    // Identity remains the Worker's job. A plain curl-shaped client still
    // reaches upstream with the expected Codex identity.
    const spy = captureRelay();
    try {
      await worker.fetch(
        new Request("https://w.example/api.openai.com/v1/responses", {
          method: "POST",
          headers: { "user-agent": "curl/8.5.0", "content-type": "application/json" },
          body: '{"model":"gpt-5.6","input":"hi"}',
        }),
        ENV,
        context(),
      );

      const signed = signedHeaders(sentRequest(spy));
      expect(signed.get("user-agent")).toMatch(/^codex-tui\//);
      expect(signed.get("originator")).toBe("codex-tui");
      expect(signed.get("user-agent")).not.toContain("curl");
    } finally {
      spy.mockRestore();
    }
  });

  // Both namespaces, not just the current one. The legacy names stay reserved
  // permanently because a live relay still reads them, so a caller that could
  // smuggle `x-codex-relay-target` through would steer this Worker's signed
  // envelope at a host of its choosing.
  it.each([
    ["current", "x-egress-relay-"],
    ["legacy", "x-codex-relay-"],
  ])("still refuses a client-forged %s relay envelope", async (_generation, prefix) => {
    // Open to callers must not mean the caller can impersonate the Worker to the
    // relay. Every relay control header is dropped before signing.
    const spy = captureRelay();
    try {
      await worker.fetch(
        new Request("https://w.example/api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            [`${prefix}target`]: "aHR0cHM6Ly9hdHRhY2tlci5leGFtcGxl",
            [`${prefix}result`]: "upstream",
            "content-type": "application/json",
          },
          body: "{}",
        }),
        ENV,
        context(),
      );

      const relayRequest = sentRequest(spy);
      // The Worker's own target wins, not the forged one.
      expect(signedTarget(relayRequest)).toBe("https://api.openai.com/v1/responses");
      expect(signedHeaders(relayRequest).has(`${prefix}result`)).toBe(false);
      expect(signedHeaders(relayRequest).has(`${prefix}target`)).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("upstream host allowlist", () => {
  const RESTRICTED: Env = { ...ENV, ALLOWED_UPSTREAM_HOSTS: "ps.air-outer.com,.openai.com" };

  it("permits any public host when unset, preserving the original contract", () => {
    // Rollback path: clearing the variable restores prior behaviour with no
    // code change, so an operator is never locked out by this feature.
    expect(isAllowedUpstreamHost("anything.example", ENV)).toBe(true);
    expect(isAllowedUpstreamHost("anything.example", { ALLOWED_UPSTREAM_HOSTS: "" })).toBe(true);
    expect(isAllowedUpstreamHost("anything.example", { ALLOWED_UPSTREAM_HOSTS: " , " })).toBe(
      true,
    );
  });

  it("allows listed hosts and rejects everything else", async () => {
    expect(isAllowedUpstreamHost("ps.air-outer.com", RESTRICTED)).toBe(true);
    // Case and trailing dot are the same identity.
    expect(isAllowedUpstreamHost("PS.Air-Outer.COM", RESTRICTED)).toBe(true);
    expect(isAllowedUpstreamHost("ps.air-outer.com.", RESTRICTED)).toBe(true);
    // A dot-prefixed entry covers the parent and its subdomains.
    expect(isAllowedUpstreamHost("openai.com", RESTRICTED)).toBe(true);
    expect(isAllowedUpstreamHost("api.openai.com", RESTRICTED)).toBe(true);
    // ...but never a sibling that merely ends with the same text.
    expect(isAllowedUpstreamHost("evil-openai.com", RESTRICTED)).toBe(false);
    expect(isAllowedUpstreamHost("attacker.example", RESTRICTED)).toBe(false);
    // And not a host that only *contains* an allowed name.
    expect(isAllowedUpstreamHost("ps.air-outer.com.attacker.example", RESTRICTED)).toBe(false);
  });

  it("rejects a disallowed target at the Worker boundary before any egress", async () => {
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        new Request("https://w.example/attacker.example/v1/steal", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }),
        RESTRICTED,
        context(),
      );

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        error: { message: "invalid target", type: "invalid_target" },
      });
      // Fail closed: the relay must not have been contacted at all.
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it("still relays an allowed target while the allowlist is active", async () => {
    // The useful direction, not just the safe one: restricting must not break
    // the host the deployment actually serves.
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        new Request("https://w.example/ps.air-outer.com/v1/responses?stream=true", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"model":"gpt-5.6-sol","input":"hi"}',
        }),
        RESTRICTED,
        context(),
      );

      expect(response.status).toBe(200);
      expect(signedTarget(sentRequest(spy))).toBe(
        "https://ps.air-outer.com/v1/responses?stream=true",
      );
    } finally {
      spy.mockRestore();
    }
  });

  it("applies the allowlist to parseTarget directly", () => {
    expect(() =>
      parseTarget(new Request("https://w.example/attacker.example/v1"), RESTRICTED),
    ).toThrow(TargetError);
    expect(
      parseTarget(new Request("https://w.example/api.openai.com/v1"), RESTRICTED).hostname,
    ).toBe("api.openai.com");
  });

  it("does not let an upstream redirect escape the allowlist", () => {
    // Without this an upstream could bounce the client to a forbidden host and
    // the Worker would relay the follow-up request there.
    const target = parseTarget(
      new Request("https://w.example/api.openai.com/v1/responses"),
      RESTRICTED,
    );
    const workerUrl = new URL("https://w.example/api.openai.com/v1/responses");

    expect(() =>
      rewriteLocation("https://attacker.example/v1/x", target, workerUrl, RESTRICTED),
    ).toThrow(RedirectError);

    // An allowed redirect is still rewritten back onto the Worker.
    expect(rewriteLocation("https://openai.com/v2/x", target, workerUrl, RESTRICTED)).toBe(
      "https://w.example/openai.com/v2/x",
    );
  });
});
