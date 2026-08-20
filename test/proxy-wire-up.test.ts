import { describe, expect, it, vi } from "vitest";

/**
 * The Worker reaches `cloudflare:sockets` through this module, so the wire-up
 * can be tested without a real TCP egress.
 */
const dial = vi.fn();
vi.mock("../src/egress/sockets", () => ({
  connectSocket: (
    address: { hostname: string; port: number },
    options: { secureTransport: string; allowHalfOpen: boolean },
  ) => dial(address, options),
}));

import worker, { type Env } from "../src/index";

const enc = (text: string) => new TextEncoder().encode(text);
const dec = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

/** VER=5 REP=0 RSV=0 ATYP=1 0.0.0.0:0 */
const CONNECT_OK = new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
const NO_AUTH = new Uint8Array([0x05, 0x00]);
const AUTH_METHOD = new Uint8Array([0x05, 0x02]);
const AUTH_OK = new Uint8Array([0x01, 0x00]);

const PROXY_URL = "socks5://relay-user:relay-pass@proxy.internal:9050";

const ENV: Env = {
  CODEX_PROXY_INSTALLATION_ID: "11111111-1111-1111-1111-111111111111",
};

function context(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

function readableOf(chunks: Uint8Array[]) {
  const queue = [...chunks];
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = queue.shift();
      if (next) controller.enqueue(next);
      else controller.close();
    },
  });
}

function collector() {
  const writes: Uint8Array[] = [];
  return {
    writable: new WritableStream<Uint8Array>({
      write(chunk) {
        writes.push(new Uint8Array(chunk));
      },
    }),
    text: () => writes.map(dec).join(""),
    bytes: () => {
      const total = writes.reduce((n, c) => n + c.byteLength, 0);
      const out = new Uint8Array(total);
      let off = 0;
      for (const c of writes) {
        out.set(c, off);
        off += c.byteLength;
      }
      return out;
    },
  };
}

function tunnel(options: {
  socksChunks: Uint8Array[];
  tlsChunks?: Uint8Array[];
  tlsReadable?: ReadableStream<Uint8Array>;
}) {
  const plain = collector();
  const tls = collector();
  const startTls = vi.fn((_opts: { expectedServerHostname: string }) => ({
    readable: options.tlsReadable ?? readableOf(options.tlsChunks ?? []),
    writable: tls.writable,
  }));
  const close = vi.fn(() => {});
  const socket = {
    readable: readableOf(options.socksChunks),
    writable: plain.writable,
    startTls,
    close,
  };
  return { socket, plain, tls, startTls, close };
}

// content-length must match the body exactly: 17 bytes.
const okResponse = enc(
  'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 17\r\nconnection: close\r\n\r\n{"object":"list"}',
);

describe("Worker proxy egress wire-up", () => {
  it("routes through the configured SOCKS5 proxy with identity projection intact", async () => {
    const fake = tunnel({
      socksChunks: [AUTH_METHOD, AUTH_OK, CONNECT_OK],
      tlsChunks: [okResponse],
    });
    dial.mockReset().mockReturnValue(fake.socket);
    const direct = vi.spyOn(globalThis, "fetch");

    try {
      const response = await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/responses?stream=true", {
          method: "POST",
          headers: {
            authorization: "Bearer client-token",
            "content-type": "application/json",
          },
          body: '{"model":"gpt-5.6-terra"}',
        }),
        { ...ENV, EGRESS_PROXY_URL: PROXY_URL },
        context(),
      );

      // Never a direct fetch when a proxy is configured.
      expect(direct).not.toHaveBeenCalled();

      // Dials the proxy from the URL, StartTLS-capable.
      expect(dial).toHaveBeenCalledTimes(1);
      expect(dial.mock.calls[0][0]).toEqual({
        hostname: "proxy.internal",
        port: 9050,
      });
      expect(dial.mock.calls[0][1].secureTransport).toBe("starttls");

      // Credentials from the URL are actually used (auth method 0x02 offered).
      expect(Array.from(fake.plain.bytes().slice(0, 4))).toEqual([
        0x05, 0x02, 0x00, 0x02,
      ]);
      // CONNECT names the upstream, so the proxy resolves it, not the Worker.
      expect(dec(fake.plain.bytes())).toContain("api.example.com");

      // TLS is validated against the upstream, never the proxy.
      expect(fake.startTls.mock.calls[0][0].expectedServerHostname).toBe(
        "api.example.com",
      );

      const sent = fake.tls.text();
      expect(sent.startsWith("POST /v1/responses?stream=true HTTP/1.1\r\n")).toBe(
        true,
      );
      expect(sent).toContain("host: api.example.com\r\n");
      expect(sent).toContain("authorization: Bearer client-token\r\n");
      // Codex identity projection still applies on the proxy path.
      expect(sent).toContain(
        "x-codex-installation-id: 11111111-1111-1111-1111-111111111111\r\n",
      );
      expect(sent).toContain("originator: codex-tui\r\n");
      expect(sent).toContain("client_metadata");

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");
      // Upstream framing headers must not be re-emitted downstream.
      expect(response.headers.has("connection")).toBe(false);
      expect(await response.text()).toBe('{"object":"list"}');
    } finally {
      direct.mockRestore();
    }
  });

  it("streams SSE from the proxy path without buffering", async () => {
    let push!: (chunk: Uint8Array) => void;
    let finish!: () => void;
    const live = new ReadableStream<Uint8Array>({
      start(controller) {
        push = (chunk) => controller.enqueue(chunk);
        finish = () => controller.close();
      },
    });

    const fake = tunnel({
      socksChunks: [NO_AUTH, CONNECT_OK],
      tlsReadable: live,
    });
    dial.mockReset().mockReturnValue(fake.socket);

    push(enc("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"));
    push(enc("data: first\n\n"));

    const response = await worker.fetch(
      new Request("https://relay.example/api.example.com/v1/responses", {
        method: "POST",
        body: "{}",
        headers: { "content-type": "application/json" },
      }),
      { ...ENV, EGRESS_PROXY_URL: "socks5://proxy.internal:9050" },
      context(),
    );

    expect(response.status).toBe(200);
    const reader = response.body!.getReader();
    const first = await reader.read();
    expect(dec(first.value!)).toContain("data: first");

    push(enc("data: second\n\n"));
    const second = await reader.read();
    expect(dec(second.value!)).toContain("data: second");

    finish();
    reader.releaseLock();
  });

  it("fails closed with 502 when the proxy refuses the connection", async () => {
    dial.mockReset().mockImplementation(() => {
      throw new Error("connection refused");
    });
    const direct = vi.spyOn(globalThis, "fetch");

    try {
      const response = await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/models"),
        { ...ENV, EGRESS_PROXY_URL: PROXY_URL },
        context(),
      );

      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({
        error: {
          message: "proxy egress failed",
          type: "proxy_unavailable",
        },
      });
      expect(direct).not.toHaveBeenCalled();
    } finally {
      direct.mockRestore();
    }
  });

  it("fails closed with 502 when SOCKS5 authentication is rejected", async () => {
    const fake = tunnel({ socksChunks: [AUTH_METHOD, new Uint8Array([0x01, 0x01])] });
    dial.mockReset().mockReturnValue(fake.socket);
    const direct = vi.spyOn(globalThis, "fetch");

    try {
      const response = await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/models"),
        { ...ENV, EGRESS_PROXY_URL: PROXY_URL },
        context(),
      );

      expect(response.status).toBe(502);
      const payload = (await response.json()) as { error: { message: string } };
      // A generic message: proxy internals and credentials stay server-side.
      expect(payload.error.message).toBe("proxy egress failed");
      const text = JSON.stringify(payload);
      expect(text).not.toContain("relay-user");
      expect(text).not.toContain("relay-pass");
      expect(text).not.toContain("proxy.internal");
      expect(direct).not.toHaveBeenCalled();
      expect(fake.startTls).not.toHaveBeenCalled();
    } finally {
      direct.mockRestore();
    }
  });

  it("fails closed with 504 when the tunnel stalls past the timeout", async () => {
    // A proxy that accepts the socket and then never answers.
    const stalled = tunnel({ socksChunks: [] });
    const socket = {
      ...stalled.socket,
      readable: new ReadableStream<Uint8Array>({ pull() {} }),
    };
    dial.mockReset().mockReturnValue(socket);

    const response = await worker.fetch(
      new Request("https://relay.example/api.example.com/v1/models"),
      {
        ...ENV,
        EGRESS_PROXY_URL: PROXY_URL,
        CODEX_PROXY_TUNNEL_TIMEOUT_MS: "50",
      },
      context(),
    );

    expect(response.status).toBe(504);
    expect(await response.json()).toEqual({
      error: { message: "proxy egress timed out", type: "proxy_timeout" },
    });
  });

  it("fails closed with 502 when EGRESS_PROXY_URL is unusable", async () => {
    dial.mockReset();
    const direct = vi.spyOn(globalThis, "fetch");

    try {
      for (const url of ["http://proxy.example:8080", "not a url"]) {
        const response = await worker.fetch(
          new Request("https://relay.example/api.example.com/v1/models"),
          { ...ENV, EGRESS_PROXY_URL: url },
          context(),
        );

        expect(response.status).toBe(502);
        expect(await response.json()).toEqual({
          error: {
            message: "configured proxy egress is unavailable",
            type: "proxy_unavailable",
          },
        });
      }

      // No socket, and above all no silent direct egress.
      expect(dial).not.toHaveBeenCalled();
      expect(direct).not.toHaveBeenCalled();
    } finally {
      direct.mockRestore();
    }
  });

  it("still uses direct egress when no proxy is configured", async () => {
    dial.mockReset();
    const direct = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(null, { status: 204 }));

    try {
      const response = await worker.fetch(
        new Request("https://relay.example/api.example.com/v1/models"),
        ENV,
        context(),
      );

      expect(response.status).toBe(204);
      expect(direct).toHaveBeenCalledTimes(1);
      expect(dial).not.toHaveBeenCalled();
    } finally {
      direct.mockRestore();
    }
  });

  it("rejects an invalid target before dialling the proxy", async () => {
    dial.mockReset();

    const response = await worker.fetch(
      new Request("https://relay.example/not a hostname/v1/models"),
      { ...ENV, EGRESS_PROXY_URL: PROXY_URL },
      context(),
    );

    expect(response.status).toBe(400);
    expect(dial).not.toHaveBeenCalled();
  });
});
