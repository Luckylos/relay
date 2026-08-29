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
      // Runs against the real wrangler.toml vars on purpose, so this covers the
      // deployed configuration and not just a hand-built env object.
      const response = await workerExports.default.fetch(
        "https://relay.example/api.openai.com/v1/models?limit=1",
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
      ).toBe("https://api.openai.com/v1/models?limit=1");
    } finally {
      upstream.mockRestore();
    }
  });

  it("relays an unlisted host, holding the deployed open-egress decision in place", async () => {
    // Guards the deployed configuration itself, not just the code. The allowlist
    // is deliberately empty, so any public HTTPS host must be reachable; if
    // someone narrowed ALLOWED_UPSTREAM_HOSTS without deciding to, this fails.
    // The paired unit tests still cover enforcement when a list IS configured,
    // so clearing the value costs no coverage of that path.
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(asUpstream(new Response(null, { status: 204 })));
    try {
      const bindings = env as unknown as {
        ALLOWED_UPSTREAM_HOSTS?: string;
        EGRESS_RELAY_URL: string;
      };
      expect((bindings.ALLOWED_UPSTREAM_HOSTS ?? "").trim()).toBe("");

      const workerExports = exports as unknown as {
        default: { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
      };
      const response = await workerExports.default.fetch(
        "https://relay.example/not-listed.example/v1/models",
      );

      expect(response.status).toBe(204);
      // Open on which hosts, never on which path: an unlisted target must still
      // leave through the signed relay, not straight out of the Worker.
      const sent = upstream.mock.calls[0]?.[0] as Request;
      expect(sent.url).toBe(bindings.EGRESS_RELAY_URL);
      expect(
        new TextDecoder().decode(
          base64UrlDecode(sent.headers.get("x-codex-relay-target") ?? ""),
        ),
      ).toBe("https://not-listed.example/v1/models");
    } finally {
      upstream.mockRestore();
    }
  });
});
