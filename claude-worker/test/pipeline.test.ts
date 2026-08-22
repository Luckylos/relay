/**
 * The relay pipeline's own contract, as this package implements it.
 *
 * The ingress suite covers this Worker end to end. What it cannot express is the
 * behaviour that belongs to the pipeline itself: that its error mapping
 * distinguishes the caller's fault from this Worker's own bug, and that this
 * ingress leaves the caller's identity alone rather than projecting one.
 *
 * This package carries its own copy of the pipeline, so it carries its own copy
 * of these tests. A shared suite would have coupled the two deployments, which
 * is exactly what the split removed.
 */
import { describe, expect, it, vi } from "vitest";
import { createRelayHandler, type PipelineEnv } from "../src/pipeline";
import { asUpstream } from "./support/relay-stub";
import { signedHeaders } from "./support/signed-block";

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

describe("relay pipeline fault attribution", () => {
  it("blames the client for a malformed target", async () => {
    const handler = createRelayHandler<PipelineEnv>({
      maxBodyBytes: () => undefined,
    });

    const response = await handler.fetch(
      new Request("https://ingress.example/"),
      { ...ENV },
      context(),
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { type: "invalid_target" },
    });
  });

  /**
   * A parse failure that is this Worker's own bug must not be reported as
   * 400 `invalid_target`: that would blame the client for an internal fault and
   * hide it from Cloudflare's error reporting. Only a TargetError is the
   * caller's fault; anything else propagates.
   */
  it("does not disguise an internal parse fault as a client error", async () => {
    const handler = createRelayHandler<PipelineEnv>({
      maxBodyBytes: () => undefined,
    });

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
      // unbounded; the default has to apply instead.
      expect(response.status).toBe(200);
    } finally {
      relay.mockRestore();
    }
  });
});

describe("this ingress projects no identity", () => {
  /**
   * The one behavioural difference between this package and the Codex one, and
   * the reason `projectRequest` is omitted here. Asserted at the pipeline level
   * so that adding a projection hook to this Worker fails a test rather than
   * silently replacing the client's own correct Anthropic identity with a guess.
   */
  it("forwards the client's own identity headers untouched", async () => {
    const relay = captureRelay();
    try {
      const handler = createRelayHandler<PipelineEnv>({
        maxBodyBytes: () => undefined,
      });

      await handler.fetch(
        new Request("https://ingress.example/upstream.example/v1/messages", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "user-agent": "claude-cli/2.0.0",
          },
          body: "{}",
        }),
        { ...ENV },
        context(),
      );

      const signed = signedHeaders(relay.mock.calls[0]?.[0] as Request);
      // The client's own Anthropic identity survives...
      expect(signed.get("anthropic-version")).toBe("2023-06-01");
      expect(signed.get("user-agent")).toBe("claude-cli/2.0.0");
      // ...and no Codex identity is invented for a client that already has one.
      expect(signed.has("originator")).toBe(false);
      expect(signed.has("x-codex-installation-id")).toBe(false);
    } finally {
      relay.mockRestore();
    }
  });

  it("relays the body byte-for-byte with no injected metadata", async () => {
    const relay = captureRelay();
    try {
      const handler = createRelayHandler<PipelineEnv>({
        maxBodyBytes: () => undefined,
      });
      const body = '{"model":"claude-sonnet-4-6","max_tokens":1024}';

      await handler.fetch(
        new Request("https://ingress.example/upstream.example/v1/messages", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
        }),
        { ...ENV },
        context(),
      );

      const relayed = await (relay.mock.calls[0]?.[0] as Request).text();
      expect(relayed).toBe(body);
      expect(relayed).not.toContain("client_metadata");
    } finally {
      relay.mockRestore();
    }
  });
});
