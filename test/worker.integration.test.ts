import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

import { base64UrlDecode } from "../src/relay/protocol";

describe("Worker integration entrypoint", () => {
  it("runs the exported Worker handler through relay egress", async () => {
    const upstream = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, {
        status: 201,
        headers: { "x-integration": "yes" },
      }),
    );

    try {
      const workerExports = exports as unknown as {
        default: { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
      };
      const response = await workerExports.default.fetch(
        "https://relay.example/second.example/v1/models?limit=1",
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
      ).toBe("https://second.example/v1/models?limit=1");
    } finally {
      upstream.mockRestore();
    }
  });
});
