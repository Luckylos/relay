import { describe, expect, it } from "vitest";
import { Socks5Error, socks5Connect } from "../src/egress/socks5";

/**
 * In-memory duplex socket shaped like the object returned by
 * `cloudflare:sockets` connect(): { readable, writable } Web Streams.
 *
 * Server bytes are delivered one queued chunk per `pull`, which lets a test
 * control datagram framing precisely — that framing is what broke the earlier
 * implementation.
 */
function fixture(serverChunks: Uint8Array[]) {
  const writes: Uint8Array[] = [];
  const queue = [...serverChunks];

  const readable = new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = queue.shift();
      if (next) {
        controller.enqueue(next);
      } else {
        // Emptied queue == peer closed the connection.
        controller.close();
      }
    },
  });

  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      writes.push(new Uint8Array(chunk));
    },
  });

  return {
    socket: { readable, writable },
    writes: () => writes,
    written: () => {
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

const bytes = (...values: number[]) => new Uint8Array(values);

const ascii = (text: string) =>
  new Uint8Array([...text].map((ch) => ch.charCodeAt(0)));

const join = (...parts: Uint8Array[]) => {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
};

/** VER=5 REP=0 RSV=0 ATYP=1 127.0.0.1:8080 */
const REPLY_OK_IPV4 = bytes(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90);

describe("socks5Connect", () => {
  it("negotiates no-auth and issues an ATYP=DOMAIN CONNECT for the target", async () => {
    const f = fixture([bytes(0x05, 0x00), REPLY_OK_IPV4]);

    await socks5Connect(f.socket, { hostname: "api.example.com", port: 443 });

    const sent = f.written();
    // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
    expect(Array.from(sent.slice(0, 3))).toEqual([0x05, 0x01, 0x00]);

    // CONNECT: VER=5 CMD=1 RSV=0 ATYP=3 LEN host PORT(be16)
    const host = ascii("api.example.com");
    const expected = join(
      bytes(0x05, 0x01, 0x00, 0x03, host.byteLength),
      host,
      bytes(0x01, 0xbb), // 443 big-endian
    );
    expect(Array.from(sent.slice(3))).toEqual(Array.from(expected));
  });

  it("sends the target hostname, never the proxy hostname", async () => {
    const f = fixture([bytes(0x05, 0x00), REPLY_OK_IPV4]);

    await socks5Connect(f.socket, { hostname: "upstream.test", port: 8443 });

    const sent = f.written();
    // Layout: 3-byte greeting, then VER CMD RSV ATYP LEN -> hostname at offset 8.
    expect(sent[7]).toBe("upstream.test".length); // ATYP=DOMAIN length byte
    const decoded = String.fromCharCode(...sent.slice(8, 8 + sent[7]));
    expect(decoded).toBe("upstream.test");
    expect(decoded).not.toContain("127.0.0.1");
    // 8443 = 0x20FB
    expect(Array.from(sent.slice(-2))).toEqual([0x20, 0xfb]);
  });

  it("performs RFC 1929 username/password authentication", async () => {
    const f = fixture([
      bytes(0x05, 0x02), // server selects username/password
      bytes(0x01, 0x00), // auth success
      REPLY_OK_IPV4,
    ]);

    await socks5Connect(
      f.socket,
      { hostname: "example.com", port: 443 },
      { username: "user", password: "pw" },
    );

    const sent = f.written();
    // Greeting must offer both no-auth and username/password.
    expect(Array.from(sent.slice(0, 4))).toEqual([0x05, 0x02, 0x00, 0x02]);

    const auth = join(
      bytes(0x01, 4),
      ascii("user"),
      bytes(2),
      ascii("pw"),
    );
    expect(Array.from(sent.slice(4, 4 + auth.byteLength))).toEqual(
      Array.from(auth),
    );
  });

  // Regression: the previous implementation issued a second read() for the
  // bound-address field even when the whole reply already arrived in one
  // datagram, producing "CONNECT bound address: proxy socket closed".
  it("parses a CONNECT reply that arrives as a single datagram", async () => {
    const f = fixture([bytes(0x05, 0x00), REPLY_OK_IPV4]);

    await expect(
      socks5Connect(f.socket, { hostname: "example.com", port: 443 }),
    ).resolves.toBeDefined();
  });

  it("parses a CONNECT reply split across several datagrams", async () => {
    const f = fixture([
      bytes(0x05, 0x00),
      bytes(0x05, 0x00),       // VER REP
      bytes(0x00, 0x01),       // RSV ATYP=IPv4
      bytes(127, 0),           // partial address
      bytes(0, 1, 0x1f),       // rest of address + high port byte
      bytes(0x90),             // low port byte
    ]);

    await expect(
      socks5Connect(f.socket, { hostname: "example.com", port: 443 }),
    ).resolves.toBeDefined();
  });

  it("parses ATYP=DOMAIN and ATYP=IPv6 bound addresses", async () => {
    const domain = ascii("bound.example");
    const domainReply = join(
      bytes(0x05, 0x00, 0x00, 0x03, domain.byteLength),
      domain,
      bytes(0x01, 0xbb),
    );
    const f1 = fixture([bytes(0x05, 0x00), domainReply]);
    await expect(
      socks5Connect(f1.socket, { hostname: "example.com", port: 443 }),
    ).resolves.toBeDefined();

    const ipv6Reply = join(
      bytes(0x05, 0x00, 0x00, 0x04),
      new Uint8Array(16),
      bytes(0x01, 0xbb),
    );
    const f2 = fixture([bytes(0x05, 0x00), ipv6Reply]);
    await expect(
      socks5Connect(f2.socket, { hostname: "example.com", port: 443 }),
    ).resolves.toBeDefined();
  });

  it("returns tunnel bytes that arrived alongside the CONNECT reply", async () => {
    const early = ascii("EARLY");
    const f = fixture([bytes(0x05, 0x00), join(REPLY_OK_IPV4, early)]);

    const result = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 443,
    });

    expect(Array.from(result.leftover)).toEqual(Array.from(early));
  });

  it("reports no leftover bytes for a clean reply", async () => {
    const f = fixture([bytes(0x05, 0x00), REPLY_OK_IPV4]);
    const result = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 443,
    });
    expect(result.leftover.byteLength).toBe(0);
  });

  it("fails closed when authentication is rejected, without leaking credentials", async () => {
    const f = fixture([
      bytes(0x05, 0x02),
      bytes(0x01, 0x01), // auth failure
    ]);

    const error = await socks5Connect(
      f.socket,
      { hostname: "example.com", port: 443 },
      { username: "s3cr3t-user", password: "s3cr3t-pass" },
    ).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Socks5Error);
    const err = error as Socks5Error;
    expect(err.code).toBe("socks5_auth_failed");
    const text = `${err.message} ${String(err)}`;
    expect(text).not.toContain("s3cr3t-user");
    expect(text).not.toContain("s3cr3t-pass");
  });

  it("rejects when the proxy demands authentication but none is configured", async () => {
    const f = fixture([bytes(0x05, 0x02)]);

    const error = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 443,
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Socks5Error);
    expect((error as Socks5Error).code).toBe("socks5_auth_required");
  });

  it("rejects when the proxy offers no acceptable method", async () => {
    const f = fixture([bytes(0x05, 0xff)]);

    const error = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 443,
    }).catch((err: unknown) => err);

    expect((error as Socks5Error).code).toBe("socks5_no_acceptable_method");
  });

  it("maps a non-zero CONNECT reply code to a target failure", async () => {
    const f = fixture([
      bytes(0x05, 0x00),
      bytes(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0), // REP=5 refused
    ]);

    const error = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 443,
    }).catch((err: unknown) => err);

    expect((error as Socks5Error).code).toBe("socks5_connect_failed");
  });

  it("rejects a non-SOCKS5 version byte", async () => {
    const f = fixture([bytes(0x04, 0x00)]);

    const error = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 443,
    }).catch((err: unknown) => err);

    expect((error as Socks5Error).code).toBe("socks5_protocol_error");
  });

  it("reports a clear error when the proxy closes mid-handshake", async () => {
    const f = fixture([]); // closes immediately

    const error = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 443,
    }).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(Socks5Error);
    expect((error as Socks5Error).code).toBe("socks5_closed");
  });

  it("rejects a hostname that cannot fit in a SOCKS5 address field", async () => {
    const f = fixture([bytes(0x05, 0x00), REPLY_OK_IPV4]);

    const error = await socks5Connect(f.socket, {
      hostname: `${"a".repeat(256)}.example.com`,
      port: 443,
    }).catch((err: unknown) => err);

    expect((error as Socks5Error).code).toBe("socks5_protocol_error");
  });

  it("rejects an out-of-range port", async () => {
    const f = fixture([bytes(0x05, 0x00), REPLY_OK_IPV4]);

    const error = await socks5Connect(f.socket, {
      hostname: "example.com",
      port: 70000,
    }).catch((err: unknown) => err);

    expect((error as Socks5Error).code).toBe("socks5_protocol_error");
  });
});
