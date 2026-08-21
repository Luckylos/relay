/**
 * Claude ingress.
 *
 * The Codex Worker's job is to *manufacture* identity. This one's job is to not
 * touch it: the real client is Claude Code, which already sends a correct
 * `user-agent`, `anthropic-version`, `anthropic-beta` and `x-api-key`. So the
 * tests that matter are (a) all of that arrives upstream byte-for-byte,
 * (b) nothing Codex-shaped gets injected, (c) the body is not rewritten, and
 * (d) the egress guarantees the architecture depends on -- mandatory relay,
 * bounded upstreams, no envelope forgery -- still hold.
 */
import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/claude/index";
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

describe("client identity passthrough", () => {
  it("forwards the Anthropic auth and version headers untouched", async () => {
    // `anthropic-version` is mandatory on every Anthropic API call and
    // `x-api-key` is the caller's own credential. Dropping or rewriting either
    // one turns every request into a 4xx.
    const spy = captureRelay();
    try {
      const response = await worker.fetch(claudeCodeRequest(), ENV, context());

      expect(response.status).toBe(200);
      const signed = signedHeaders(sentRequest(spy));
      expect(signed.get("x-api-key")).toBe("sk-ant-test-key");
      expect(signed.get("anthropic-version")).toBe("2023-06-01");
      expect(signed.get("anthropic-beta")).toBe(
        "fine-grained-tool-streaming-2025-05-14",
      );
    } finally {
      spy.mockRestore();
    }
  });

  it("preserves the client's own user-agent instead of synthesizing one", async () => {
    // The deliberate divergence from the Codex Worker, which overwrites
    // user-agent with `codex-tui/...`. Here the client's identity is the
    // correct one, so replacing it would substitute a guess for the truth.
    const spy = captureRelay();
    try {
      await worker.fetch(claudeCodeRequest(), ENV, context());

      const signed = signedHeaders(sentRequest(spy));
      expect(signed.get("user-agent")).toBe("claude-cli/2.1.185 (external, cli)");
      expect(signed.get("user-agent")).not.toMatch(/codex/i);
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

  it("relays the request body byte-for-byte", async () => {
    // The Codex path injects `client_metadata` into JSON bodies. Doing that to a
    // Messages API request would corrupt a payload the client composed itself,
    // and the signed body digest would then cover content the caller never sent.
    const body = '{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}';
    const spy = captureRelay();
    try {
      await worker.fetch(claudeCodeRequest(body), ENV, context());

      const relayed = await sentRequest(spy).text();
      expect(relayed).toBe(body);
      expect(relayed).not.toContain("client_metadata");
    } finally {
      spy.mockRestore();
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
