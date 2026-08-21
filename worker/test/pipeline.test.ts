/**
 * The shared pipeline's own contract.
 *
 * The per-ingress suites cover each Worker end to end. What they cannot express
 * is the behaviour that belongs to the pipeline itself: that its error mapping
 * distinguishes the caller's fault from this Worker's own bug, and that the one
 * hook the ingresses differ on -- identity projection -- is applied for Codex
 * and skipped for Claude rather than being applied to both or neither.
 *
 * Those two properties are why the pipeline was extracted, so they are tested
 * against `createRelayHandler` directly instead of being inferred from the two
 * deployments happening to work.
 */
import { describe, expect, it, vi } from "vitest";
import { createRelayHandler, type PipelineEnv } from "../src/pipeline";
import codexWorker from "../src/index";
import claudeWorker from "../src/claude/index";
import { base64UrlDecode } from "../src/relay/protocol";
import { asUpstream } from "./support/relay-stub";

const ENV = {
  EGRESS_RELAY_URL: "https://relay.internal.example/v1/forward",
  EGRESS_RELAY_KEY_ID: "key-1",
  EGRESS_RELAY_SECRET: "relay-test-secret",
} satisfies PipelineEnv;

function context(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

function captureRelay() {
  return vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(asUpstream(new Response("ok", { status: 200 })));
}

/**
 * Reads the upstream header names back out of the signed block the relay stub
 * received, which is the only place to observe what projection actually did.
 */
function projectedHeaderNames(relay: ReturnType<typeof captureRelay>): Set<string> {
  const sent = relay.mock.calls[0]?.[0] as Request;
  const raw = sent.headers.get("x-codex-relay-headers") ?? "";
  const block = new TextDecoder().decode(base64UrlDecode(raw));
  const names = new Set<string>();
  for (const line of block.split("\n")) {
    if (line.length === 0) continue;
    names.add(line.slice(0, line.indexOf(":")).toLowerCase());
  }
  return names;
}

describe("shared relay pipeline", () => {
  it("blames the client for a malformed target", async () => {
    const response = await claudeWorker.fetch(
      new Request("https://ingress.example/"),
      { ...ENV } as never,
      context(),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { type: "invalid_target" },
    });
  });

  /**
   * The Codex entrypoint used to catch every parse failure and answer 400
   * `invalid_target`, including failures that were this Worker's own bug. That
   * turned an internal fault into a lie about the caller's request and hid it
   * from Cloudflare's error reporting, so the pipeline now lets a non-TargetError
   * propagate. This test is what keeps the old, quieter behaviour from returning.
   */
  it("does not disguise an internal parse fault as a client error", async () => {
    const handler = createRelayHandler<PipelineEnv>({
      maxBodyBytes: () => undefined,
    });

    // A getter that throws stands in for a bug inside target parsing: it is
    // reached during parseTarget, and it is not a TargetError.
    const request = new Request("https://ingress.example/upstream.example/v1/x");
    Object.defineProperty(request, "url", {
      get() {
        throw new TypeError("internal parse fault");
      },
    });

    await expect(handler.fetch(request, { ...ENV }, context())).rejects.toThrow(
      "internal parse fault",
    );
  });

  it("reports a failed identity projection as this Worker's fault, not the caller's", async () => {
    const handler = createRelayHandler<PipelineEnv>({
      maxBodyBytes: () => undefined,
      projectRequest: () => {
        throw new Error("projection failed");
      },
    });

    const response = await handler.fetch(
      new Request("https://ingress.example/upstream.example/v1/x", { method: "POST", body: "{}" }),
      { ...ENV },
      context(),
    );

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toMatchObject({
      error: { type: "upstream_error" },
    });
  });

  it("falls back to the default ceiling when the ingress variable is malformed", async () => {
    const relay = captureRelay();
    try {
      const handler = createRelayHandler<PipelineEnv & { CEILING?: string }>({
        maxBodyBytes: (env) => env.CEILING,
      });

      const response = await handler.fetch(
        new Request("https://ingress.example/upstream.example/v1/x", {
          method: "POST",
          body: "small",
        }),
        { ...ENV, CEILING: "not-a-number" },
        context(),
      );

      // A NaN ceiling would have compared false and let the body through
      // unbounded; the default has to apply instead, and a small body still
      // passes under it.
      expect(response.status).toBe(200);
    } finally {
      relay.mockRestore();
    }
  });
});

describe("ingress projection differences", () => {
  const CODEX_ENV = {
    ...ENV,
    CODEX_PROXY_INSTALLATION_ID: "11111111-1111-1111-1111-111111111111",
  };

  it("synthesizes Codex identity on the Codex ingress", async () => {
    const relay = captureRelay();
    try {
      await codexWorker.fetch(
        new Request("https://ingress.example/upstream.example/v1/responses", {
          method: "POST",
          headers: { "content-type": "application/json", "user-agent": "curl/8.0" },
          body: "{}",
        }),
        CODEX_ENV as never,
        context(),
      );

      const names = projectedHeaderNames(relay);
      expect(names.has("originator")).toBe(true);
      expect(names.has("x-codex-installation-id")).toBe(true);
    } finally {
      relay.mockRestore();
    }
  });

  it("forwards the client's own identity on the Claude ingress", async () => {
    const relay = captureRelay();
    try {
      await claudeWorker.fetch(
        new Request("https://ingress.example/upstream.example/v1/messages", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "user-agent": "claude-cli/2.0.0",
          },
          body: "{}",
        }),
        { ...ENV } as never,
        context(),
      );

      const names = projectedHeaderNames(relay);
      // The client's own Anthropic identity survives...
      expect(names.has("anthropic-version")).toBe(true);
      // ...and no Codex identity is invented for a client that already has one.
      expect(names.has("originator")).toBe(false);
      expect(names.has("x-codex-installation-id")).toBe(false);
    } finally {
      relay.mockRestore();
    }
  });
});
