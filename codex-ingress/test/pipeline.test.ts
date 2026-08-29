/**
 * The relay pipeline's own contract, as this package implements it.
 *
 * The ingress suites cover this Worker end to end. What they cannot express is
 * the behaviour that belongs to the pipeline itself: that its error mapping
 * distinguishes the caller's fault from this Worker's own bug. Those rules were
 * regressions once already, so they are tested against `createRelayHandler`
 * directly rather than inferred from the deployment happening to work.
 *
 * This package carries its own copy of the pipeline, so it carries its own copy
 * of these tests. A shared suite would have coupled the two deployments, which
 * is exactly what the split removed.
 */
import { describe, expect, it, vi } from "vitest";
import { createRelayHandler, type PipelineEnv } from "../src/pipeline";
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
    // Synthesizing identity is this package's job, so a failure in it is a 502,
    // never a 4xx blaming the client for a request it composed correctly.
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
    const relay = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(asUpstream(new Response("ok", { status: 200 })));
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
