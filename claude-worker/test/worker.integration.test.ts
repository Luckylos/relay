import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

import { base64UrlDecode } from "../src/relay/protocol";
import { asUpstream } from "./support/relay-stub";

describe("Worker integration entrypoint", () => {
  it("runs the exported Worker handler through relay egress", async () => {
    const upstream = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      asUpstream(
        new Response(null, {
          status: 201,
          headers: { "x-integration": "yes" },
        }),
      ),
    );

    try {
      const workerExports = exports as unknown as {
        default: { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
      };
      // No credential: real bindings must relay an unadorned client request.
      // The host must be one the production ALLOWED_UPSTREAM_HOSTS permits,
      // since this suite deliberately runs against the real wrangler.toml vars.
      const response = await workerExports.default.fetch(
        "https://relay.example/api.anthropic.com/v1/models?limit=1",
      );

      expect(response.status).toBe(201);
      expect(await response.text()).toBe("");
      expect(response.headers.get("x-integration")).toBe("yes");

      // The real bindings must route through the relay, not the upstream host.
      const sent = upstream.mock.calls[0]?.[0] as Request;
      const bindings = env as unknown as { EGRESS_RELAY_URL: string };
      expect(sent.url).toBe(bindings.EGRESS_RELAY_URL);
      expect(
        new TextDecoder().decode(
          base64UrlDecode(sent.headers.get("x-codex-relay-target") ?? ""),
        ),
      ).toBe("https://api.anthropic.com/v1/models?limit=1");
    } finally {
      upstream.mockRestore();
    }
  });

  it("enforces the configured upstream allowlist through the real bindings", async () => {
    // Guards the deployed configuration itself, not just the code: if
    // ALLOWED_UPSTREAM_HOSTS were dropped from wrangler.toml, the Worker would
    // silently become an open proxy egressing from the relay's address.
    const upstream = vi.spyOn(globalThis, "fetch");
    try {
      const workerExports = exports as unknown as {
        default: { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
      };
      const response = await workerExports.default.fetch(
        "https://relay.example/not-allowed.example/v1/models",
      );

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        error: { message: "invalid target", type: "invalid_target" },
      });
      expect(upstream).not.toHaveBeenCalled();
    } finally {
      upstream.mockRestore();
    }
  });
});
