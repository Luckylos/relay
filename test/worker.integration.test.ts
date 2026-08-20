import { exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";

describe("Worker integration entrypoint", () => {
  it("runs the exported Worker handler through dynamic direct egress", async () => {
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
      expect(upstream.mock.calls[0]?.[0]).toBe(
        "https://second.example/v1/models?limit=1",
      );
    } finally {
      upstream.mockRestore();
    }
  });
});
