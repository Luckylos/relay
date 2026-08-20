/**
 * Minimal HTTP/1.1 client framing for a single request over an established
 * TLS tunnel.
 *
 * Scope is deliberately narrow: one request per tunnel (`connection: close`),
 * so there is no keep-alive bookkeeping, no pipelining and no HTTP/2 framing.
 *
 * The response body is exposed as a `ReadableStream` that pulls lazily from the
 * socket. Nothing is buffered beyond the current chunk, which is what keeps
 * server-sent events arriving incrementally instead of at end-of-response.
 */

export type Http1ErrorCode = "http1_protocol_error" | "http1_closed";

export class Http1Error extends Error {
  constructor(
    readonly code: Http1ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "Http1Error";
  }
}

/** Guards against a hostile or broken peer streaming an unbounded head. */
const MAX_HEAD_BYTES = 64 * 1024;

/**
 * Request headers the relay must control itself. Client-supplied values are
 * dropped so a caller cannot spoof the tunnel target (`host`) or desynchronise
 * message framing (`content-length`, `transfer-encoding`).
 */
const EXCLUDED_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "upgrade",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
]);

/**
 * Response headers describing the upstream wire framing. They must not reach
 * the downstream response, whose framing is re-established independently.
 */
const STRIPPED_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
  "content-length",
  "upgrade",
]);

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export interface Http1RequestInit {
  method: string;
  /** Origin-form request target, e.g. `/v1/responses?stream=true`. */
  target: string;
  /** Real upstream hostname, used for the `Host` header. */
  hostname: string;
  headers: Headers;
  body: Uint8Array;
}

export interface Http1Response {
  status: number;
  statusText: string;
  headers: Headers;
  body: ReadableStream<Uint8Array> | null;
}

/**
 * Serialises the request head. The body is written separately by the caller so
 * large payloads never need to be copied into a second buffer.
 */
export function buildRequest(init: Http1RequestInit): Uint8Array {
  const lines: string[] = [
    `${init.method.toUpperCase()} ${init.target} HTTP/1.1`,
    `host: ${init.hostname}`,
  ];

  for (const [name, value] of init.headers) {
    const lower = name.toLowerCase();
    if (EXCLUDED_REQUEST_HEADERS.has(lower)) continue;
    lines.push(`${lower}: ${value}`);
  }

  if (init.body.byteLength > 0) {
    lines.push(`content-length: ${init.body.byteLength}`);
  }
  // One request per tunnel: ask the peer to close so a body with no explicit
  // framing terminates deterministically.
  lines.push("connection: close");

  return encoder.encode(`${lines.join("\r\n")}\r\n\r\n`);
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.byteLength === 0) return right;
  if (right.byteLength === 0) return left;
  const out = new Uint8Array(left.byteLength + right.byteLength);
  out.set(left, 0);
  out.set(right, left.byteLength);
  return out;
}

function indexOfCrlf(bytes: Uint8Array, from = 0): number {
  for (let i = from; i + 1 < bytes.byteLength; i += 1) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) return i;
  }
  return -1;
}

function indexOfHeadEnd(bytes: Uint8Array): number {
  for (let i = 0; i + 3 < bytes.byteLength; i += 1) {
    if (
      bytes[i] === 0x0d &&
      bytes[i + 1] === 0x0a &&
      bytes[i + 2] === 0x0d &&
      bytes[i + 3] === 0x0a
    ) {
      return i;
    }
  }
  return -1;
}

const STATUS_LINE = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/;

/**
 * Reads and parses the response head, then returns the body as a lazily pulled
 * stream.
 *
 * `leftover` carries bytes that arrived in the same datagram as the proxy's
 * CONNECT reply. Discarding them loses the first packet of the response, so
 * they are parsed ahead of anything read from the socket.
 */
export async function readResponse(
  readable: ReadableStream<Uint8Array>,
  leftover?: Uint8Array,
): Promise<Http1Response> {
  const reader = readable.getReader();
  let buffer =
    leftover && leftover.byteLength > 0 ? leftover : new Uint8Array(0);

  let headEnd = indexOfHeadEnd(buffer);
  while (headEnd < 0) {
    const { done, value } = await reader.read();
    if (done) {
      throw new Http1Error(
        "http1_closed",
        "upstream closed before the response head was complete",
      );
    }
    if (value && value.byteLength > 0) buffer = concat(buffer, value);
    if (buffer.byteLength > MAX_HEAD_BYTES) {
      throw new Http1Error("http1_protocol_error", "response head too large");
    }
    headEnd = indexOfHeadEnd(buffer);
  }

  const headLines = decoder.decode(buffer.subarray(0, headEnd)).split("\r\n");
  let pending = buffer.subarray(headEnd + 4);

  const match = STATUS_LINE.exec(headLines[0] ?? "");
  if (!match) {
    throw new Http1Error("http1_protocol_error", "malformed status line");
  }
  const status = Number(match[1]);
  const statusText = match[2] ?? "";

  const headers = new Headers();
  let chunked = false;
  let contentLength: number | null = null;

  for (const line of headLines.slice(1)) {
    if (!line) continue;
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();

    if (name === "transfer-encoding") {
      chunked = value.toLowerCase().includes("chunked");
    } else if (name === "content-length") {
      const parsed = Number(value);
      if (Number.isInteger(parsed) && parsed >= 0) contentLength = parsed;
    }

    if (STRIPPED_RESPONSE_HEADERS.has(name)) continue;
    headers.append(name, value);
  }

  // Responses that cannot carry a body by definition.
  const bodyless = status === 204 || status === 304 || status < 200;
  if (bodyless || contentLength === 0) {
    reader.releaseLock();
    return { status, statusText, headers, body: null };
  }

  const fail = (
    controller: ReadableStreamDefaultController<Uint8Array>,
    message: string,
  ) => {
    controller.error(new Http1Error("http1_closed", message));
  };

  /** Pulls one more datagram into `pending`. False means the peer closed. */
  const fill = async (): Promise<boolean> => {
    const { done, value } = await reader.read();
    if (done) return false;
    if (value && value.byteLength > 0) pending = concat(pending, value);
    return true;
  };

  let body: ReadableStream<Uint8Array>;

  if (chunked) {
    type Phase = "size" | "data" | "crlf" | "done";
    let phase: Phase = "size";
    let remaining = 0;

    body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        for (;;) {
          if (phase === "done") {
            controller.close();
            return;
          }

          if (phase === "size") {
            const idx = indexOfCrlf(pending);
            if (idx < 0) {
              if (!(await fill())) {
                fail(controller, "upstream closed inside a chunked body");
                return;
              }
              continue;
            }
            const line = decoder.decode(pending.subarray(0, idx)).trim();
            // A chunk-size line may carry extensions after ';'.
            const size = Number.parseInt(line.split(";")[0] ?? "", 16);
            if (!Number.isInteger(size) || size < 0) {
              controller.error(
                new Http1Error("http1_protocol_error", "invalid chunk size"),
              );
              return;
            }
            pending = pending.subarray(idx + 2);
            if (size === 0) {
              phase = "done";
              controller.close();
              return;
            }
            remaining = size;
            phase = "data";
            continue;
          }

          if (phase === "data") {
            if (pending.byteLength === 0) {
              if (!(await fill())) {
                fail(controller, "upstream closed inside a chunked body");
                return;
              }
              continue;
            }
            const take = pending.subarray(
              0,
              Math.min(remaining, pending.byteLength),
            );
            pending = pending.subarray(take.byteLength);
            remaining -= take.byteLength;
            if (remaining === 0) phase = "crlf";
            // Hand this chunk over immediately; buffering here is what would
            // stall an event stream.
            controller.enqueue(take);
            return;
          }

          // Consume the CRLF that terminates a chunk.
          while (pending.byteLength < 2) {
            if (!(await fill())) {
              fail(controller, "upstream closed inside a chunked body");
              return;
            }
          }
          pending = pending.subarray(2);
          phase = "size";
        }
      },
      async cancel() {
        await reader.cancel().catch(() => {});
      },
    });
  } else if (contentLength !== null) {
    let remaining = contentLength;

    body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        for (;;) {
          if (remaining === 0) {
            controller.close();
            return;
          }
          if (pending.byteLength > 0) {
            const take = pending.subarray(
              0,
              Math.min(remaining, pending.byteLength),
            );
            pending = pending.subarray(take.byteLength);
            remaining -= take.byteLength;
            controller.enqueue(take);
            if (remaining === 0) controller.close();
            return;
          }
          if (!(await fill())) {
            fail(
              controller,
              "upstream closed before content-length bytes arrived",
            );
            return;
          }
        }
      },
      async cancel() {
        await reader.cancel().catch(() => {});
      },
    });
  } else {
    // No explicit framing: the body runs until the peer closes.
    body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (pending.byteLength > 0) {
          const take = pending;
          pending = new Uint8Array(0);
          controller.enqueue(take);
          return;
        }
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        if (value && value.byteLength > 0) controller.enqueue(value);
      },
      async cancel() {
        await reader.cancel().catch(() => {});
      },
    });
  }

  return { status, statusText, headers, body };
}
