import { describe, expect, it } from "vitest";
import { Http1Error, buildRequest, readResponse } from "../src/egress/http1";

const enc = (text: string) => new TextEncoder().encode(text);
const dec = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

/**
 * Manually driven readable stream. Tests control exactly when bytes appear,
 * which is what makes the streaming assertions meaningful: if the parser
 * buffered a whole body, a read would hang instead of resolving.
 */
function stream() {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const readable = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
    },
  });
  return {
    readable,
    push: (text: string | Uint8Array) =>
      controller.enqueue(typeof text === "string" ? enc(text) : text),
    close: () => controller.close(),
  };
}

async function drain(body: ReadableStream<Uint8Array> | null) {
  if (!body) return "";
  const chunks: Uint8Array[] = [];
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  const total = chunks.reduce((n, c) => n + c.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return dec(out);
}

describe("buildRequest", () => {
  it("writes an origin-form request line and the target Host header", () => {
    const bytes = buildRequest({
      method: "POST",
      target: "/v1/responses?stream=true",
      hostname: "api.example.com",
      headers: new Headers({ authorization: "Bearer token" }),
      body: enc('{"a":1}'),
    });

    const text = dec(bytes);
    expect(text.startsWith("POST /v1/responses?stream=true HTTP/1.1\r\n")).toBe(
      true,
    );
    expect(text).toContain("host: api.example.com\r\n");
    // The credential must travel verbatim. Redaction belongs in error messages,
    // never in the bytes on the wire, or upstream auth breaks.
    expect(text).toContain("authorization: Bearer token\r\n");
    expect(text).not.toContain("***");
    // Head only: the caller writes the body separately.
    expect(text.endsWith("\r\n\r\n")).toBe(true);
  });

  it("sets content-length from the body and omits it when there is no body", () => {
    const withBody = dec(
      buildRequest({
        method: "POST",
        target: "/x",
        hostname: "h.test",
        headers: new Headers(),
        body: enc("12345"),
      }),
    );
    expect(withBody).toContain("content-length: 5\r\n");

    const withoutBody = dec(
      buildRequest({
        method: "GET",
        target: "/x",
        hostname: "h.test",
        headers: new Headers(),
        body: new Uint8Array(0),
      }),
    );
    expect(withoutBody).not.toContain("content-length:");
  });

  it("drops hop-by-hop and client-supplied framing headers", () => {
    const text = dec(
      buildRequest({
        method: "GET",
        target: "/x",
        hostname: "real.test",
        headers: new Headers({
          host: "spoofed.test",
          connection: "keep-alive",
          "transfer-encoding": "chunked",
          "content-length": "999",
          "proxy-authorization": "Basic leak",
          accept: "text/event-stream",
        }),
        body: new Uint8Array(0),
      }),
    );

    expect(text).toContain("host: real.test\r\n");
    expect(text).not.toContain("spoofed.test");
    expect(text).not.toContain("keep-alive");
    expect(text).not.toContain("transfer-encoding");
    expect(text).not.toContain("999");
    expect(text).not.toContain("Basic leak");
    // Legitimate headers survive.
    expect(text).toContain("accept: text/event-stream\r\n");
  });

  it("closes the connection because each tunnel serves one request", () => {
    const text = dec(
      buildRequest({
        method: "GET",
        target: "/",
        hostname: "h.test",
        headers: new Headers(),
        body: new Uint8Array(0),
      }),
    );
    expect(text).toContain("connection: close\r\n");
  });
});

describe("readResponse", () => {
  it("parses status, reason phrase and headers", async () => {
    const s = stream();
    s.push(
      "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
    );
    s.close();

    const res = await readResponse(s.readable);
    expect(res.status).toBe(404);
    expect(res.statusText).toBe("Not Found");
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(await drain(res.body)).toBe("{}");
  });

  it("tolerates a status line with no reason phrase", async () => {
    const s = stream();
    s.push("HTTP/1.1 200\r\ncontent-length: 0\r\n\r\n");
    s.close();

    const res = await readResponse(s.readable);
    expect(res.status).toBe(200);
    expect(res.statusText).toBe("");
  });

  it("reads a content-length delimited body", async () => {
    const s = stream();
    s.push("HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nhello world");
    s.close();

    const res = await readResponse(s.readable);
    expect(await drain(res.body)).toBe("hello world");
  });

  it("reassembles a chunked body and strips the chunked framing header", async () => {
    const s = stream();
    s.push(
      "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" +
        "5\r\nhello\r\n" +
        "1\r\n \r\n" +
        "5\r\nworld\r\n" +
        "0\r\n\r\n",
    );
    s.close();

    const res = await readResponse(s.readable);
    // Framing must not leak downstream or the response gets double-framed.
    expect(res.headers.has("transfer-encoding")).toBe(false);
    expect(await drain(res.body)).toBe("hello world");
  });

  it("reads a body delimited only by connection close", async () => {
    const s = stream();
    s.push("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\n");
    s.push("part-one ");
    s.push("part-two");
    s.close();

    const res = await readResponse(s.readable);
    expect(await drain(res.body)).toBe("part-one part-two");
  });

  it("prepends leftover bytes captured with the SOCKS5 CONNECT reply", async () => {
    // The head arrived early, alongside the CONNECT reply. Dropping it here is
    // exactly how a tunnel loses its first packet.
    const leftover = enc("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nearly");
    const s = stream();
    s.close();

    const res = await readResponse(s.readable, leftover);
    expect(res.status).toBe(200);
    expect(await drain(res.body)).toBe("early");
  });

  it("keeps body bytes that share a datagram with the head", async () => {
    const s = stream();
    s.push("HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nbody");
    s.close();

    const res = await readResponse(s.readable);
    expect(await drain(res.body)).toBe("body");
  });

  it("parses a head split across several datagrams", async () => {
    const s = stream();
    s.push("HTTP/1.");
    s.push("1 201 Created\r\ncont");
    s.push("ent-length: 2\r\n");
    s.push("\r\nok");
    s.close();

    const res = await readResponse(s.readable);
    expect(res.status).toBe(201);
    expect(res.statusText).toBe("Created");
    expect(await drain(res.body)).toBe("ok");
  });

  // The streaming guarantee: an SSE event must be readable before the next one
  // exists. A buffering implementation makes this read hang.
  it("surfaces an SSE event before the next event is produced", async () => {
    const s = stream();
    s.push("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n");
    s.push("data: one\n\n");

    const res = await readResponse(s.readable);
    const reader = res.body!.getReader();

    const first = await reader.read();
    expect(dec(first.value!)).toContain("data: one");

    s.push("data: two\n\n");
    const second = await reader.read();
    expect(dec(second.value!)).toContain("data: two");

    s.close();
    reader.releaseLock();
  });

  it("streams chunked events incrementally", async () => {
    const s = stream();
    s.push("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
    s.push("b\r\ndata: one\n\n\r\n");

    const res = await readResponse(s.readable);
    const reader = res.body!.getReader();

    const first = await reader.read();
    expect(dec(first.value!)).toContain("data: one");

    s.push("0\r\n\r\n");
    const end = await reader.read();
    expect(end.done).toBe(true);
    reader.releaseLock();
  });

  it("reports no body for a 204 response", async () => {
    const s = stream();
    s.push("HTTP/1.1 204 No Content\r\n\r\n");
    s.close();

    const res = await readResponse(s.readable);
    expect(res.status).toBe(204);
    expect(await drain(res.body)).toBe("");
  });

  it("preserves a header value containing a colon", async () => {
    const s = stream();
    s.push(
      "HTTP/1.1 200 OK\r\nlocation: https://example.com:8443/x\r\ncontent-length: 0\r\n\r\n",
    );
    s.close();

    const res = await readResponse(s.readable);
    expect(res.headers.get("location")).toBe("https://example.com:8443/x");
  });

  it("rejects a malformed status line", async () => {
    const s = stream();
    s.push("GARBAGE\r\n\r\n");
    s.close();

    const error = await readResponse(s.readable).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(Http1Error);
    expect((error as Http1Error).code).toBe("http1_protocol_error");
  });

  it("rejects a connection closed before the head completed", async () => {
    const s = stream();
    s.push("HTTP/1.1 200 OK\r\ncontent-len");
    s.close();

    const error = await readResponse(s.readable).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(Http1Error);
    expect((error as Http1Error).code).toBe("http1_closed");
  });
});
