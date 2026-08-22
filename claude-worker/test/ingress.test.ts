/**
 * Claude ingress.
 *
 * Both Workers rewrite client identity; they disagree on *whose*. The Codex
 * Worker manufactures a Codex client. This one presents a Claude Code client,
 * rebuilt from one pinned profile on every request rather than forwarded from
 * the caller -- a caller's own values describe its machine, its CLI build and
 * its session, and mixing those with this Worker's produces a client that never
 * shipped.
 *
 * So the tests that matter are (a) the identity headers and body are rebuilt to
 * the profile, (b) the caller's upstream *credential* is still forwarded
 * untouched, since this Worker holds none of its own, (c) nothing Codex-shaped
 * leaks into a Claude request, and (d) the egress guarantees the architecture
 * depends on -- mandatory relay, bounded upstreams, no envelope forgery -- still
 * hold.
 */
import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";
import { RedirectError, rewriteLocation } from "../src/redirect";
import { parseTarget, TargetError } from "../src/target";
import { asUpstream } from "./support/relay-stub";
import { signedHeaders, signedTarget } from "./support/signed-block";

const ENV: Env = {
  EGRESS_RELAY_URL: "https://relay.internal.example/v1/forward",
  EGRESS_RELAY_KEY_ID: "key-1",
  EGRESS_RELAY_SECRET: "relay-test-secret",
  ALLOWED_UPSTREAM_HOSTS: "ps.air-outer.com,.anthropic.com",
};

function context(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

function captureRelay(response = new Response('{"type":"message"}', { status: 200 })) {
  return vi.spyOn(globalThis, "fetch").mockResolvedValue(asUpstream(response));
}

function sentRequest(spy: ReturnType<typeof captureRelay>): Request {
  return spy.mock.calls[0]?.[0] as Request;
}

/** A request shaped the way Claude Code actually sends one. */
function claudeCodeRequest(body = '{"model":"claude-sonnet-4-6","max_tokens":1024}'): Request {
  return new Request("https://w.example/api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": "sk-ant-test-key",
      "anthropic-version": "2023-06-01",
      "anthropic-beta": "fine-grained-tool-streaming-2025-05-14",
      "content-type": "application/json",
      "user-agent": "claude-cli/2.1.185 (external, cli)",
      accept: "application/json",
    },
    body,
  });
}

describe("Claude Code cloak", () => {
  it("forwards the caller's credential while rebuilding the profile headers", async () => {
    // The split that matters. `x-api-key` is the caller's own upstream
    // credential and this Worker has none to substitute, so rewriting it would
    // simply break the request. `anthropic-version` is the SDK's pinned API
    // version, so it is rebuilt -- to the same value a real client sends.
    const spy = captureRelay();
    try {
      const response = await worker.fetch(claudeCodeRequest(), ENV, context());

      expect(response.status).toBe(200);
      const signed = signedHeaders(sentRequest(spy));
      expect(signed.get("x-api-key")).toBe("sk-ant-test-key");
      expect(signed.get("anthropic-version")).toBe("2023-06-01");
      // Derived value first, then the caller's unrecognised beta at the tail:
      // an unknown value is far more likely to be a feature newer than this
      // Worker than an error worth discarding.
      expect(signed.get("anthropic-beta")).toBe(
        "claude-code-20250219,fine-grained-tool-streaming-2025-05-14",
      );
    } finally {
      spy.mockRestore();
    }
  });

  it("rebuilds the client profile over the caller's stale one", async () => {
    // The fixture sends 2.1.185 -- an older CLI than the pinned profile. Its
    // values must not survive: a 2.1.185 user-agent arriving with this profile's
    // SDK version would describe a combination that was never released.
    const spy = captureRelay();
    try {
      await worker.fetch(claudeCodeRequest(), ENV, context());

      const signed = signedHeaders(sentRequest(spy));
      expect(signed.get("user-agent")).toBe("claude-cli/2.1.239 (external, cli)");
      expect(signed.get("user-agent")).not.toMatch(/2\.1\.185/);
      expect(signed.get("user-agent")).not.toMatch(/codex/i);

      // The whole Stainless set is rebuilt together, including the two headers a
      // CPA-derived baseline omits (`lang` and `runtime`).
      expect(signed.get("x-stainless-lang")).toBe("js");
      expect(signed.get("x-stainless-runtime")).toBe("node");
      expect(signed.get("x-stainless-package-version")).toBe("0.112.1");
      expect(signed.get("x-stainless-runtime-version")).toBe("v26.3.0");
      // Claims the host it actually runs on, not a more exotic one.
      expect(signed.get("x-stainless-os")).toBe("Linux");
      expect(signed.get("x-stainless-arch")).toBe("x64");
      expect(signed.get("x-stainless-retry-count")).toBe("0");
      expect(signed.get("x-app")).toBe("cli");
    } finally {
      spy.mockRestore();
    }
  });

  it("drops the caller's real Claude Code session identity", async () => {
    // A caller that is genuinely running Claude Code sends its own session and
    // agent ids. Forwarding them alongside this Worker's derived identity would
    // put two different machines behind one credential.
    const spy = captureRelay();
    try {
      await worker.fetch(
        new Request("https://w.example/api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-claude-code-session-id": "11111111-2222-3333-4444-555555555555",
            "x-claude-code-agent-id": "agent-9",
            "x-claude-remote-session-id": "remote-9",
            "anthropic-client-platform": "desktop_app",
          },
          body: "{}",
        }),
        ENV,
        context(),
      );

      const signed = signedHeaders(sentRequest(spy));
      for (const name of [
        "x-claude-code-session-id",
        "x-claude-code-agent-id",
        "x-claude-remote-session-id",
        "anthropic-client-platform",
      ]) {
        expect(signed.has(name)).toBe(false);
      }
    } finally {
      spy.mockRestore();
    }
  });

  it("injects no Codex identity headers", async () => {
    const spy = captureRelay();
    try {
      await worker.fetch(claudeCodeRequest(), ENV, context());

      const signed = signedHeaders(sentRequest(spy));
      for (const name of [
        "originator",
        "session-id",
        "thread-id",
        "x-client-request-id",
        "x-codex-window-id",
        "x-codex-installation-id",
        "x-codex-beta-features",
        "x-codex-turn-metadata",
      ]) {
        expect(signed.has(name)).toBe(false);
      }
    } finally {
      spy.mockRestore();
    }
  });

  it("forwards the prompt untouched and stamps only the identity", async () => {
    // The prompt is the caller's. Nothing is prepended to `system`, no date
    // reminder is appended and no cache breakpoint is planted: an inserted block
    // shifts the prompt prefix and costs the caller its own cache hits, and
    // injected text changes what the model answers.
    const body =
      '{"model":"claude-sonnet-4-6","max_tokens":1024,"system":"be terse","messages":[{"role":"user","content":"hi"}]}';
    const spy = captureRelay();
    try {
      await worker.fetch(claudeCodeRequest(body), ENV, context());

      const relayed = JSON.parse(await sentRequest(spy).text());
      expect(relayed.model).toBe("claude-sonnet-4-6");
      expect(relayed.max_tokens).toBe(1024);
      expect(relayed.messages).toEqual([{ role: "user", content: "hi" }]);
      // Still the caller's bare string: not promoted to a block array, not
      // reordered, nothing added.
      expect(relayed.system).toBe("be terse");
      expect(relayed.context_management).toBeUndefined();
      // `user_id` is a JSON string, not a nested object: an object here would be
      // immediately distinguishable from a real request.
      const userId = JSON.parse(relayed.metadata.user_id);
      expect(userId.device_id).toMatch(/^[0-9a-f]{64}$/);
      // Authentic for API-key auth: the real client sends "" with no OAuth
      // account, so inventing a UUID would be less accurate, not more.
      expect(userId.account_uuid).toBe("");
      // Codex's body field must never appear on a Claude request.
      expect(relayed.client_metadata).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
  });

  it("is idempotent across a second hop", async () => {
    // A request can traverse more than one hop of this Worker, so each pass must
    // converge on the same bytes. It does because the only field written is
    // `metadata.user_id`, and that is derived from the credential rather than
    // accumulated.
    const first = captureRelay();
    let relayed: string;
    let firstSigned: Map<string, string>;
    try {
      await worker.fetch(claudeCodeRequest(), ENV, context());
      relayed = await sentRequest(first).text();
      firstSigned = signedHeaders(sentRequest(first));
    } finally {
      first.mockRestore();
    }

    // The next hop receives exactly what this one sent upstream, so the replay is
    // built from the signed block rather than from a hand-written header set.
    // That also carries the caller's credential through unchanged, which matters:
    // identity is derived from the API key, so a replay that dropped it would
    // derive a different device and session and fail for the wrong reason.
    const replayHeaders = new Headers();
    for (const [name, value] of firstSigned) {
      replayHeaders.set(name, value);
    }

    const second = captureRelay();
    try {
      await worker.fetch(
        new Request("https://w.example/api.anthropic.com/v1/messages", {
          method: "POST",
          headers: replayHeaders,
          body: relayed,
        }),
        ENV,
        context(),
      );

      // Body byte-identical across hops.
      expect(await sentRequest(second).text()).toBe(relayed);
      // And the rebuilt headers converge too, including the beta list.
      expect(Object.fromEntries(signedHeaders(sentRequest(second)))).toEqual(
        Object.fromEntries(firstSigned),
      );
    } finally {
      second.mockRestore();
    }
  });

  it("works for a client that sends only a base URL and a key", async () => {
    // Zero-config is the product requirement: no Worker credential, no custom
    // header. A bare curl must reach the upstream.
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        new Request("https://w.example/api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "x-api-key": "k", "content-type": "application/json" },
          body: "{}",
        }),
        ENV,
        context(),
      );

      expect(response.status).toBe(200);
      expect(signedTarget(sentRequest(spy))).toBe("https://api.anthropic.com/v1/messages");
    } finally {
      spy.mockRestore();
    }
  });
});

describe("egress guarantees", () => {
  it("refuses a client-forged relay envelope", async () => {
    // Being open to callers must not let a caller impersonate the Worker to the
    // relay. Every x-codex-relay-* header is dropped before signing.
    const spy = captureRelay();
    try {
      await worker.fetch(
        new Request("https://w.example/api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "x-codex-relay-target": "aHR0cHM6Ly9hdHRhY2tlci5leGFtcGxl",
            "x-codex-relay-result": "upstream",
            "content-type": "application/json",
          },
          body: "{}",
        }),
        ENV,
        context(),
      );

      const relayRequest = sentRequest(spy);
      expect(signedTarget(relayRequest)).toBe("https://api.anthropic.com/v1/messages");
      expect(signedHeaders(relayRequest).has("x-codex-relay-result")).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });

  it("never leaks relay control headers to the client", async () => {
    const spy = captureRelay();
    try {
      const response = await worker.fetch(claudeCodeRequest(), ENV, context());

      for (const [name] of response.headers) {
        expect(name.toLowerCase().startsWith("x-codex-relay-")).toBe(false);
      }
    } finally {
      spy.mockRestore();
    }
  });

  it("rejects an upstream outside the allowlist before any egress", async () => {
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        new Request("https://w.example/api.openai.com/v1/messages", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }),
        ENV,
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

  it("allows the Anthropic domain and its subdomains", () => {
    expect(parseTarget(new Request("https://w.example/api.anthropic.com/v1"), ENV).hostname).toBe(
      "api.anthropic.com",
    );
    expect(parseTarget(new Request("https://w.example/anthropic.com/v1"), ENV).hostname).toBe(
      "anthropic.com",
    );
    expect(parseTarget(new Request("https://w.example/ps.air-outer.com/v1"), ENV).hostname).toBe(
      "ps.air-outer.com",
    );
    // A sibling that merely ends with the same text is not the same domain.
    expect(() =>
      parseTarget(new Request("https://w.example/evil-anthropic.com/v1"), ENV),
    ).toThrow(TargetError);
  });

  it("fails closed when relay egress is not configured", async () => {
    // The relay is the only egress path. Falling back to the Worker's own
    // Cloudflare egress would silently change which IP the upstream sees.
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        claudeCodeRequest(),
        { ALLOWED_UPSTREAM_HOSTS: ENV.ALLOWED_UPSTREAM_HOSTS },
        context(),
      );

      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({
        error: { message: "relay egress is unavailable", type: "relay_unavailable" },
      });
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it("rejects a body over the ceiling", async () => {
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        new Request("https://w.example/api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "x".repeat(64),
        }),
        { ...ENV, CLAUDE_PROXY_MAX_BODY_BYTES: "32" },
        context(),
      );

      expect(response.status).toBe(413);
      expect(await response.json()).toEqual({
        error: { message: "request body too large", type: "request_too_large" },
      });
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it("falls back to the default ceiling on a malformed value", async () => {
    // A NaN ceiling would compare false against every size and disable the limit.
    const spy = captureRelay();
    try {
      const response = await worker.fetch(
        claudeCodeRequest(),
        { ...ENV, CLAUDE_PROXY_MAX_BODY_BYTES: "not-a-number" },
        context(),
      );

      expect(response.status).toBe(200);
    } finally {
      spy.mockRestore();
    }
  });

  it("rewrites an upstream redirect back onto the Worker", () => {
    // Left alone, a redirect-following client would reach the upstream from its
    // own IP and bypass the fixed VPS egress.
    const target = parseTarget(
      new Request("https://w.example/api.anthropic.com/v1/messages"),
      ENV,
    );
    const workerUrl = new URL("https://w.example/api.anthropic.com/v1/messages");

    expect(rewriteLocation("https://api.anthropic.com/v2/messages", target, workerUrl, ENV)).toBe(
      "https://w.example/api.anthropic.com/v2/messages",
    );
    expect(() =>
      rewriteLocation("https://attacker.example/v1/x", target, workerUrl, ENV),
    ).toThrow(RedirectError);
  });

  it("streams an SSE response through unbuffered", async () => {
    // Claude Code streams by default, so the response body must be passed
    // through as a stream rather than collected.
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("event: message_start\n\n"));
        controller.close();
      },
    });
    const spy = captureRelay(
      new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } }),
    );
    try {
      const response = await worker.fetch(claudeCodeRequest(), ENV, context());

      expect(response.headers.get("content-type")).toBe("text/event-stream");
      expect(await response.text()).toContain("message_start");
    } finally {
      spy.mockRestore();
    }
  });
});
