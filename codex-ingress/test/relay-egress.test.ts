import { describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";
import { base64UrlDecode } from "../src/relay/protocol";
import { asUpstream } from "./support/relay-stub";


const ENV: Env = {
  CODEX_PROXY_INSTALLATION_ID: "11111111-1111-1111-1111-111111111111",
  CODEX_PROXY_MAX_BODY_BYTES: "1024",
  EGRESS_RELAY_URL: "https://relay.internal.example/v1/forward",
  EGRESS_RELAY_KEY_ID: "key-1",
  EGRESS_RELAY_SECRET: "relay-test-secret",
};

function context(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

function decodeUtf8(value: string | null): string {
  return new TextDecoder().decode(base64UrlDecode(value ?? ""));
}

function headerBlock(request: Request): Map<string, string> {
  const block = decodeUtf8(request.headers.get("x-codex-relay-headers"));
  const parsed = new Map<string, string>();
  for (const line of block.split("\n")) {
    if (line.length === 0) continue;
    const separator = line.indexOf(":");
    parsed.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return parsed;
}

function sseBody() {
  let releaseSecond!: () => void;
  const secondReady = new Promise<void>((resolve) => {
    releaseSecond = resolve;
  });
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("data: first\n\n"));
      void secondReady.then(() => {
        controller.enqueue(new TextEncoder().encode("data: second\n\n"));
        controller.close();
      });
    },
  });
  return { body, releaseSecond };
}

describe("Worker relay egress", () => {
  it("relays dynamic target, identity/body projection, and streams the response", async () => {
    const { body, releaseSecond } = sseBody();
    const upstream = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      asUpstream(
        new Response(body, {
          status: 207,
          statusText: "Multi-Status",
          headers: {
            "content-type": "text/event-stream",
            "content-encoding": "gzip",
            connection: "close",
            "transfer-encoding": "chunked",
            "x-upstream-marker": "yes",
          },
        }),
      ),
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

      // Relay responses reach the client unchanged apart from connection-scoped
      // header hygiene, and stream rather than buffer.
      expect(response.status).toBe(207);
      expect(response.statusText).toBe("Multi-Status");
      expect(response.headers.get("content-type")).toBe("text/event-stream");
      expect(response.headers.get("content-encoding")).toBe("gzip");
      expect(response.headers.get("x-upstream-marker")).toBe("yes");
      expect(response.headers.has("connection")).toBe(false);
      expect(response.headers.has("transfer-encoding")).toBe(false);
      expect(new TextDecoder().decode(first?.value)).toBe("data: first\n\n");

      // Egress goes to the fixed relay endpoint, never straight to the upstream.
      const sent = upstream.mock.calls[0]?.[0] as Request;
      expect(sent.url).toBe(ENV.EGRESS_RELAY_URL);
      expect(sent.method).toBe("POST");
      expect(decodeUtf8(sent.headers.get("x-codex-relay-target"))).toBe(
        "https://api.example.com/v1/responses?stream=true&x=1",
      );
      expect(sent.headers.get("x-codex-relay-method")).toBe("POST");

      // Identity projection still applies, now carried in the signed block.
      const forwarded = headerBlock(sent);
      expect(forwarded.get("authorization")).toBe("Bearer client-token");
      expect(forwarded.get("session-id")).toBeTruthy();
      expect(forwarded.has("x-codex-installation-id")).toBe(false);
      expect(forwarded.has("accept-encoding")).toBe(false);

      expect(JSON.parse(new TextDecoder().decode(await sent.arrayBuffer()))).toMatchObject({
        model: "gpt-5.6-terra",
        client_metadata: {
          "x-codex-installation-id": ENV.CODEX_PROXY_INSTALLATION_ID,
          session_id: forwarded.get("session-id"),
          thread_id: forwarded.get("thread-id"),
          "x-codex-window-id": forwarded.get("x-codex-window-id"),
        },
      });

      releaseSecond();
      const second = await reader?.read();
      expect(new TextDecoder().decode(second?.value)).toBe("data: second\n\n");
    } finally {
      upstream.mockRestore();
    }
  });

  it("never leaks relay control headers from the client into the signed block", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(asUpstream(new Response(null, { status: 204 })));

    try {
      await worker.fetch(
        new Request("https://relay.example/example.com/v1/models", {
          headers: {
            // The retired ingress header is still stripped by the prefix rule.
            "x-codex-relay-token": "retired-header-value",
            // A client must not be able to forge envelope fields or pin its own
            // signature by sending control headers.
            "x-codex-relay-key-id": "forged",
            "x-codex-relay-signature": "forged",
            connection: "close",
          },
        }),
        ENV,
        context(),
      );

      const sent = upstream.mock.calls[0]?.[0] as Request;
      const forwarded = headerBlock(sent);
      expect([...forwarded.keys()].some((name) => name.startsWith("x-codex-relay-"))).toBe(
        false,
      );
      expect(forwarded.has("connection")).toBe(false);
      expect(sent.headers.get("x-codex-relay-key-id")).toBe(ENV.EGRESS_RELAY_KEY_ID);
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

  it("fails closed with 502 when the relay URL is unusable", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("unexpected direct fallback"));
    try {
      for (const url of [
        "http://relay.internal.example/v1/forward",
        "https://user:pass@relay.internal.example/v1/forward",
        "not-a-url",
      ]) {
        const response = await worker.fetch(
          new Request("https://relay.example/example.com/v1/models"),
          { ...ENV, EGRESS_RELAY_URL: url },
          context(),
        );

        expect(response.status, `${url} must fail closed`).toBe(502);
        expect(await response.json()).toEqual({
          error: { message: "relay egress is unavailable", type: "relay_unavailable" },
        });
      }
      expect(upstream).not.toHaveBeenCalled();
    } finally {
      upstream.mockRestore();
    }
  });

  it("returns a generic 502 when the relay call fails", async () => {
    const upstream = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error("secret relay hostname detail"));
    try {
      const response = await worker.fetch(
        new Request("https://relay.example/example.com/v1/models"),
        ENV,
        context(),
      );

      expect(response.status).toBe(502);
      // No relay hostname, signing detail or upstream error text.
      expect(await response.json()).toEqual({
        error: { message: "relay egress failed", type: "relay_unavailable" },
      });
    } finally {
      upstream.mockRestore();
    }
  });

  // Migrated from the retired SOCKS5 egress suite, which asserted that proxy
  // credentials never reached a client-visible error. The signing secret is this
  // architecture's equivalent long-lived credential, so the contract still binds:
  // it authenticates the Worker to the relay and must never leave the Worker.
  it("never exposes the relay signing secret to the client or the wire", async () => {
    const SECRET = "s3cret-relay-signing-key";
    const env: Env = { ...ENV, EGRESS_RELAY_SECRET: SECRET };

    // Error path: an upstream failure whose own message embeds the secret, which
    // is the shape a careless relay client or logger would produce.
    const failing = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error(`relay rejected key ${SECRET}`));
    try {
      const response = await worker.fetch(
        new Request("https://relay.example/example.com/v1/models"),
        env,
        context(),
      );
      expect(response.status).toBe(502);
      expect(await response.text()).not.toContain(SECRET);
    } finally {
      failing.mockRestore();
    }

    // Success path: the secret proves possession via the HMAC, so it must never
    // travel as a header or body value on the outbound relay request.
    const sending = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(asUpstream(new Response("ok", { status: 200 })));
    try {
      await worker.fetch(
        new Request("https://relay.example/example.com/v1/models", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: '{"model":"probe"}',
        }),
        env,
        context(),
      );

      const sent = sending.mock.calls[0]?.[0] as Request;
      for (const [name, value] of sent.headers) {
        expect(value, `${name} must not carry the secret`).not.toContain(SECRET);
      }
      expect(new TextDecoder().decode(await sent.arrayBuffer())).not.toContain(SECRET);
    } finally {
      sending.mockRestore();
    }
  });
});
