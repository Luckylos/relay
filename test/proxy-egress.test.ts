import { describe, expect, it, vi } from "vitest";
import {
  ProxyConfigError,
  ProxyError,
  parseProxyUrl,
  sendViaProxy,
  type ProxySocket,
} from "../src/egress/proxy";
import { parseTarget } from "../src/target";

const enc = (text: string) => new TextEncoder().encode(text);
const dec = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

/** VER=5 REP=0 RSV=0 ATYP=1 0.0.0.0:0 — a clean CONNECT success reply. */
const CONNECT_OK = new Uint8Array([
  0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
]);

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
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      writes.push(new Uint8Array(chunk));
    },
  });
  return {
    writable,
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

/**
 * Fake `cloudflare:sockets` socket. The plaintext leg answers the SOCKS5
 * handshake; `startTls()` hands back a second leg carrying the HTTP response,
 * mirroring how the real runtime returns a fresh Socket.
 */
function fakeSocket(options: {
  socksChunks: Uint8Array[];
  tlsChunks: Uint8Array[];
}) {
  const plain = collector();
  const tls = collector();
  const startTls = vi.fn((_opts: { expectedServerHostname: string }) => ({
    readable: readableOf(options.tlsChunks),
    writable: tls.writable,
  }));
  const close = vi.fn(() => {});

  const socket = {
    readable: readableOf(options.socksChunks),
    writable: plain.writable,
    startTls,
    close,
  } as unknown as ProxySocket;

  return { socket, plain, tls, startTls, close };
}

const target = (url: string) => parseTarget(new Request(url));

const SOCKS5_PROXY = {
  hostname: "proxy.internal",
  port: 9050,
  credentials: { username: "u", password: "p" },
};

const okResponse = enc(
  "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 7\r\n\r\n{\"a\":1}",
);

describe("parseProxyUrl", () => {
  it("parses a socks5 URL with credentials", () => {
    const config = parseProxyUrl("socks5://alice:s3cret@10.0.0.5:1080");
    expect(config.hostname).toBe("10.0.0.5");
    expect(config.port).toBe(1080);
    expect(config.credentials).toEqual({
      username: "alice",
      password: "s3cret",
    });
  });

  it("treats socks5h the same as socks5 because CONNECT already sends a domain", () => {
    const config = parseProxyUrl("socks5h://host.test:9050");
    expect(config.hostname).toBe("host.test");
    expect(config.port).toBe(9050);
    expect(config.credentials).toBeUndefined();
  });

  it("defaults to port 1080 when the URL omits one", () => {
    expect(parseProxyUrl("socks5://host.test").port).toBe(1080);
  });

  it("percent-decodes credentials so special characters survive", () => {
    const config = parseProxyUrl("socks5://a%40b:p%3Ass%2F1@host.test:1080");
    expect(config.credentials).toEqual({
      username: "a@b",
      password: "p:ss/1",
    });
  });

  it("rejects an http proxy because HTTP CONNECT is not implemented", () => {
    const error = (() => {
      try {
        parseProxyUrl("http://proxy.test:8080");
        return undefined;
      } catch (err) {
        return err;
      }
    })();

    expect(error).toBeInstanceOf(ProxyConfigError);
    expect((error as ProxyConfigError).code).toBe("proxy_unsupported_scheme");
  });

  it("rejects a malformed proxy URL", () => {
    expect(() => parseProxyUrl("not a url")).toThrow(ProxyConfigError);
    expect(() => parseProxyUrl("")).toThrow(ProxyConfigError);
  });

  it("never places credentials in a configuration error message", () => {
    const error = (() => {
      try {
        // Valid userinfo, unusable port.
        parseProxyUrl("socks5://leaky-user:leaky-pass@host.test:999999");
        return undefined;
      } catch (err) {
        return err;
      }
    })();

    const text = `${(error as Error).message} ${String(error)}`;
    expect(text).not.toContain("leaky-user");
    expect(text).not.toContain("leaky-pass");
  });
});

describe("sendViaProxy", () => {
  it("tunnels through SOCKS5, starts TLS and returns the upstream response", async () => {
    const fake = fakeSocket({
      socksChunks: [new Uint8Array([0x05, 0x02]), new Uint8Array([0x01, 0x00]), CONNECT_OK],
      tlsChunks: [okResponse],
    });
    const connect = vi.fn(() => fake.socket);

    const response = await sendViaProxy({
      target: target("https://relay.test/api.example.com/v1/models?limit=1"),
      method: "GET",
      headers: new Headers({ authorization: "Bearer token" }),
      body: new Uint8Array(0),
      proxy: SOCKS5_PROXY,
      connect,
    });

    // Dials the proxy, not the upstream, and asks for a StartTLS-capable socket.
    expect(connect).toHaveBeenCalledTimes(1);
    const [address, options] = connect.mock.calls[0] as unknown as [
      { hostname: string; port: number },
      { secureTransport?: string },
    ];
    expect(address).toEqual({ hostname: "proxy.internal", port: 9050 });
    expect(options.secureTransport).toBe("starttls");

    // CONNECT carries the upstream hostname as ATYP=DOMAIN.
    const handshake = fake.plain.bytes();
    expect(Array.from(handshake.slice(0, 4))).toEqual([0x05, 0x02, 0x00, 0x02]);
    expect(dec(handshake).includes("api.example.com")).toBe(true);

    // The security-critical assertion: TLS is validated against the upstream.
    expect(fake.startTls).toHaveBeenCalledTimes(1);
    expect(fake.startTls.mock.calls[0][0].expectedServerHostname).toBe(
      "api.example.com",
    );

    // The HTTP request goes over the TLS leg with the real path and Host.
    const sent = fake.tls.text();
    expect(sent.startsWith("GET /v1/models?limit=1 HTTP/1.1\r\n")).toBe(true);
    expect(sent).toContain("host: api.example.com\r\n");
    expect(sent).toContain("authorization: Bearer token\r\n");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(await response.text()).toBe('{"a":1}');
  });

  it("never validates TLS against the proxy hostname", async () => {
    const fake = fakeSocket({
      socksChunks: [new Uint8Array([0x05, 0x00]), CONNECT_OK],
      tlsChunks: [okResponse],
    });

    await sendViaProxy({
      target: target("https://relay.test/upstream.example/v1/x"),
      method: "GET",
      headers: new Headers(),
      body: new Uint8Array(0),
      proxy: { hostname: "proxy.internal", port: 1080 },
      connect: () => fake.socket,
    });

    const servername = fake.startTls.mock.calls[0][0].expectedServerHostname;
    expect(servername).toBe("upstream.example");
    expect(servername).not.toBe("proxy.internal");
  });

  it("writes the request body after the head", async () => {
    const fake = fakeSocket({
      socksChunks: [new Uint8Array([0x05, 0x00]), CONNECT_OK],
      tlsChunks: [okResponse],
    });

    await sendViaProxy({
      target: target("https://relay.test/api.example.com/v1/responses"),
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      body: enc('{"stream":true}'),
      proxy: { hostname: "proxy.internal", port: 1080 },
      connect: () => fake.socket,
    });

    const sent = fake.tls.text();
    expect(sent).toContain("content-length: 15\r\n");
    expect(sent.endsWith('{"stream":true}')).toBe(true);
  });

  // On a TLS tunnel the bytes after the CONNECT reply are TLS records, and the
  // platform owns the handshake once startTls() is called, so bytes already
  // pulled off the socket cannot be pushed back. Extra bytes therefore mean the
  // stream is desynchronised: fail closed rather than start TLS mid-stream.
  it("fails closed when the proxy sends bytes after the CONNECT reply", async () => {
    const trailing = enc("unexpected");
    const merged = new Uint8Array(CONNECT_OK.byteLength + trailing.byteLength);
    merged.set(CONNECT_OK, 0);
    merged.set(trailing, CONNECT_OK.byteLength);

    const fake = fakeSocket({
      socksChunks: [new Uint8Array([0x05, 0x00]), merged],
      tlsChunks: [],
    });

    const error = await sendViaProxy({
      target: target("https://relay.test/api.example.com/v1/x"),
      method: "GET",
      headers: new Headers(),
      body: new Uint8Array(0),
      proxy: { hostname: "proxy.internal", port: 1080 },
      connect: () => fake.socket,
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(ProxyError);
    expect((error as ProxyError).code).toBe("proxy_protocol_error");
    // Never hand a desynchronised stream to the TLS layer.
    expect(fake.startTls).not.toHaveBeenCalled();
    expect(fake.close).toHaveBeenCalled();
  });

  it("streams an SSE response instead of buffering it", async () => {
    let push!: (chunk: Uint8Array) => void;
    let finish!: () => void;
    const live = new ReadableStream<Uint8Array>({
      start(controller) {
        push = (chunk) => controller.enqueue(chunk);
        finish = () => controller.close();
      },
    });

    const tlsLeg = collector();
    const socket = {
      readable: readableOf([new Uint8Array([0x05, 0x00]), CONNECT_OK]),
      writable: collector().writable,
      startTls: vi.fn(() => ({ readable: live, writable: tlsLeg.writable })),
      close: vi.fn(),
    } as unknown as ProxySocket;

    push(enc("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"));
    push(enc("data: one\n\n"));

    const response = await sendViaProxy({
      target: target("https://relay.test/api.example.com/v1/responses"),
      method: "POST",
      headers: new Headers(),
      body: new Uint8Array(0),
      proxy: { hostname: "proxy.internal", port: 1080 },
      connect: () => socket,
    });

    const reader = response.body!.getReader();
    const first = await reader.read();
    expect(dec(first.value!)).toContain("data: one");

    push(enc("data: two\n\n"));
    const second = await reader.read();
    expect(dec(second.value!)).toContain("data: two");

    finish();
    reader.releaseLock();
  });

  it("fails closed and closes the socket when SOCKS5 auth is rejected", async () => {
    const fake = fakeSocket({
      socksChunks: [new Uint8Array([0x05, 0x02]), new Uint8Array([0x01, 0x01])],
      tlsChunks: [],
    });

    const error = await sendViaProxy({
      target: target("https://relay.test/api.example.com/v1/x"),
      method: "GET",
      headers: new Headers(),
      body: new Uint8Array(0),
      proxy: {
        hostname: "proxy.internal",
        port: 1080,
        credentials: { username: "leaky-user", password: "leaky-pass" },
      },
      connect: () => fake.socket,
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Error);
    // TLS must never be attempted once the tunnel failed.
    expect(fake.startTls).not.toHaveBeenCalled();
    expect(fake.close).toHaveBeenCalled();

    const text = `${(error as Error).message} ${String(error)}`;
    expect(text).not.toContain("leaky-user");
    expect(text).not.toContain("leaky-pass");
  });

  it("propagates a proxy dial failure without falling back to direct egress", async () => {
    const connect = vi.fn(() => {
      throw new Error("connection refused");
    });

    const error = await sendViaProxy({
      target: target("https://relay.test/api.example.com/v1/x"),
      method: "GET",
      headers: new Headers(),
      body: new Uint8Array(0),
      proxy: SOCKS5_PROXY,
      connect: connect as never,
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Error);
    expect(connect).toHaveBeenCalledTimes(1);
  });
});
