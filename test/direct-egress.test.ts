import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";

const ENV: Env = {
  CODEX_PROXY_INSTALLATION_ID: "11111111-1111-1111-1111-111111111111",
  CODEX_PROXY_MAX_BODY_BYTES: "1024",
};

function context(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

function sseBody() {
  let releaseSecond!: () => void;
  const secondReady = new Promise<void>((resolve) => {
    releaseSecond = resolve;
  });
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("data: first\\n\\n"));
      void secondReady.then(() => {
        controller.enqueue(new TextEncoder().encode("data: second\\n\\n"));
        controller.close();
      });
    },
  });
  return { body, releaseSecond };
}

describe("direct Worker egress", () => {
  it("forwards dynamic target, identity/body projection, and streams the response", async () => {
    const { body, releaseSecond } = sseBody();
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        new Response(body, {
          status: 207,
          statusText: "Multi-Status",
          headers: {
            "content-type": "text/event-stream",
            "content-encoding": "gzip",
            "connection": "close",
            "transfer-encoding": "chunked",
            "x-upstream-marker": "yes",
          },
        }),
      );

    try {
      const request = new Request(
        "https://relay.example/api.example.com/v1/responses?stream=true&x=1",
        {
          method: "POST",
          headers: {
            authorization: "Bearer client-token",
            "content-type": "application/json",
          },
          body: '{"model":"gpt-5.6-terra","stream":true}',
        },
      );
      const response = await worker.fetch(request, ENV, context());
      const reader = response.body?.getReader();
      const first = await reader?.read();

      expect(response.status).toBe(207);
      expect(response.statusText).toBe("Multi-Status");
      expect(response.headers.get("content-type")).toBe("text/event-stream");
      expect(response.headers.get("content-encoding")).toBe("gzip");
      expect(response.headers.get("x-upstream-marker")).toBe("yes");
      expect(response.headers.has("connection")).toBe(false);
      expect(response.headers.has("transfer-encoding")).toBe(false);
      expect(new TextDecoder().decode(first?.value)).toBe("data: first\\n\\n");

      const [url, init] = upstream.mock.calls[0] ?? [];
      expect(url).toBe("https://api.example.com/v1/responses?stream=true&x=1");
      expect(init?.method).toBe("POST");
      expect(init?.redirect).toBe("manual");
      expect(init?.headers).toBeInstanceOf(Headers);
      const forwardedHeaders = init?.headers as Headers;
      expect(forwardedHeaders.get("authorization")).toBe("Bearer client-token");
      expect(forwardedHeaders.get("session-id")).toBeTruthy();
      expect(forwardedHeaders.get("x-codex-installation-id")).toBe(
        ENV.CODEX_PROXY_INSTALLATION_ID,
      );
      expect(JSON.parse(new TextDecoder().decode(init?.body as Uint8Array))).toMatchObject({
        model: "gpt-5.6-terra",
        client_metadata: {
          "x-codex-installation-id": ENV.CODEX_PROXY_INSTALLATION_ID,
          session_id: forwardedHeaders.get("session-id"),
          thread_id: forwardedHeaders.get("thread-id"),
          "x-codex-window-id": forwardedHeaders.get("x-codex-window-id"),
        },
      });

      releaseSecond();
      const second = await reader?.read();
      expect(new TextDecoder().decode(second?.value)).toBe("data: second\\n\\n");
    } finally {
      upstream.mockRestore();
    }
  });

  it("returns 400 invalid_target without making an outbound request", async () => {
    const upstream = vi.spyOn(globalThis, "fetch");
    try {
      const response = await worker.fetch(
        new Request("https://relay.example/not a hostname/path"),
        ENV,
        context(),
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

  it("returns 413 when the buffered request body exceeds the configured limit", async () => {
    const upstream = vi.spyOn(globalThis, "fetch");
    try {
      const response = await worker.fetch(
        new Request("https://relay.example/example.com/v1/responses", {
          method: "POST",
          body: "1234567890123456789012345678901234567890",
        }),
        { ...ENV, CODEX_PROXY_MAX_BODY_BYTES: "32" },
        context(),
      );

      expect(response.status).toBe(413);
      expect(await response.json()).toEqual({
        error: { message: "request body too large", type: "request_too_large" },
      });
      expect(upstream).not.toHaveBeenCalled();
    } finally {
      upstream.mockRestore();
    }
  });

  it("fails closed when a proxy is configured but proxy egress is unavailable", async () => {
    const upstream = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("unexpected direct fallback"));
    try {
      const response = await worker.fetch(
        new Request("https://relay.example/example.com/v1/models"),
        { ...ENV, EGRESS_PROXY_URL: "http://proxy.example:8080" },
        context(),
      );

      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({
        error: { message: "configured proxy egress is unavailable", type: "proxy_unavailable" },
      });
      expect(upstream).not.toHaveBeenCalled();
    } finally {
      upstream.mockRestore();
    }
  });

  it("returns a generic 502 when direct fetch fails", async () => {
    const upstream = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("secret upstream detail"));
    try {
      const response = await worker.fetch(
        new Request("https://relay.example/example.com/v1/models"),
        ENV,
        context(),
      );

      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({
        error: { message: "upstream request failed", type: "upstream_error" },
      });
    } finally {
      upstream.mockRestore();
    }
  });
});
