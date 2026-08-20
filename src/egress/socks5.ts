/**
 * Minimal SOCKS5 client for Cloudflare Workers.
 *
 * Implemented directly from RFC 1928 (SOCKS5) and RFC 1929 (username/password
 * auth) against the duplex `{ readable, writable }` shape returned by
 * `cloudflare:sockets` connect(). No third-party code is used here, so this
 * module carries no external licence obligations.
 *
 * Two behaviours are deliberate and load-bearing:
 *
 *  1. The CONNECT reply is parsed out of a rolling buffer. A previous attempt
 *     issued a fresh read() for the bound-address field even when the entire
 *     reply had already arrived in one datagram, which surfaced as
 *     "CONNECT bound address: proxy socket closed during handshake".
 *  2. Errors never interpolate credentials, so a failing proxy cannot leak the
 *     username or password into a response body or log line.
 */

export type Socks5ErrorCode =
  | "socks5_protocol_error"
  | "socks5_auth_required"
  | "socks5_auth_failed"
  | "socks5_no_acceptable_method"
  | "socks5_connect_failed"
  | "socks5_closed";

export class Socks5Error extends Error {
  readonly code: Socks5ErrorCode;

  constructor(code: Socks5ErrorCode, message: string) {
    super(message);
    this.name = "Socks5Error";
    this.code = code;
  }
}

export interface Socks5Target {
  hostname: string;
  port: number;
}

export interface Socks5Credentials {
  username: string;
  password: string;
}

export interface Socks5Socket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

export interface Socks5Result {
  /**
   * Tunnel bytes that the proxy sent in the same datagram as the CONNECT reply.
   * A well-behaved proxy sends none; the caller must not discard any that do
   * appear, or the first bytes of the tunnelled protocol are lost.
   */
  leftover: Uint8Array;
}

const AUTH_NONE = 0x00;
const AUTH_USERPASS = 0x02;
const AUTH_NO_ACCEPTABLE = 0xff;

const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;

const MAX_FIELD_BYTES = 255;

const encoder = new TextEncoder();

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.byteLength === 0) return right;
  if (right.byteLength === 0) return left;
  const out = new Uint8Array(left.byteLength + right.byteLength);
  out.set(left, 0);
  out.set(right, left.byteLength);
  return out;
}

/**
 * Buffers socket bytes so a field can be satisfied from data already received.
 * Reads are strictly sequential and always awaited, which keeps the reader lock
 * free of outstanding promises when it is finally released.
 */
class ByteReader {
  private buffer: Uint8Array = new Uint8Array(0);

  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}

  async need(count: number, phase: string): Promise<void> {
    while (this.buffer.byteLength < count) {
      const { value, done } = await this.reader.read();
      if (done) {
        throw new Socks5Error(
          "socks5_closed",
          `proxy closed the connection during ${phase}`,
        );
      }
      if (value && value.byteLength > 0) {
        this.buffer = concat(this.buffer, value);
      }
    }
  }

  take(count: number): Uint8Array {
    const out = this.buffer.slice(0, count);
    this.buffer = this.buffer.slice(count);
    return out;
  }

  get rest(): Uint8Array {
    return this.buffer;
  }
}

function assertTarget(target: Socks5Target): Uint8Array {
  const host = encoder.encode(target.hostname);
  if (host.byteLength === 0 || host.byteLength > MAX_FIELD_BYTES) {
    throw new Socks5Error(
      "socks5_protocol_error",
      "target hostname does not fit in a SOCKS5 address field",
    );
  }
  if (
    !Number.isInteger(target.port) ||
    target.port < 1 ||
    target.port > 0xffff
  ) {
    throw new Socks5Error(
      "socks5_protocol_error",
      "target port is out of range",
    );
  }
  return host;
}

function buildGreeting(hasCredentials: boolean): Uint8Array {
  return hasCredentials
    ? new Uint8Array([0x05, 0x02, AUTH_NONE, AUTH_USERPASS])
    : new Uint8Array([0x05, 0x01, AUTH_NONE]);
}

function buildAuth(credentials: Socks5Credentials): Uint8Array {
  const user = encoder.encode(credentials.username);
  const pass = encoder.encode(credentials.password);
  if (user.byteLength > MAX_FIELD_BYTES || pass.byteLength > MAX_FIELD_BYTES) {
    // Deliberately does not echo the offending value.
    throw new Socks5Error(
      "socks5_protocol_error",
      "proxy credentials exceed the SOCKS5 field limit",
    );
  }
  const out = new Uint8Array(3 + user.byteLength + pass.byteLength);
  let offset = 0;
  out[offset++] = 0x01; // RFC 1929 sub-negotiation version
  out[offset++] = user.byteLength;
  out.set(user, offset);
  offset += user.byteLength;
  out[offset++] = pass.byteLength;
  out.set(pass, offset);
  return out;
}

function buildConnect(host: Uint8Array, port: number): Uint8Array {
  const out = new Uint8Array(5 + host.byteLength + 2);
  let offset = 0;
  out[offset++] = 0x05; // VER
  out[offset++] = 0x01; // CMD = CONNECT
  out[offset++] = 0x00; // RSV
  out[offset++] = ATYP_DOMAIN; // let the proxy resolve the target
  out[offset++] = host.byteLength;
  out.set(host, offset);
  offset += host.byteLength;
  out[offset++] = (port >> 8) & 0xff;
  out[offset] = port & 0xff;
  return out;
}

function connectFailureMessage(reply: number): string {
  switch (reply) {
    case 0x01:
      return "proxy reported a general SOCKS server failure";
    case 0x02:
      return "proxy ruleset denied the connection";
    case 0x03:
      return "proxy reported the network is unreachable";
    case 0x04:
      return "proxy reported the host is unreachable";
    case 0x05:
      return "proxy reported the connection was refused";
    case 0x06:
      return "proxy reported TTL expired";
    case 0x07:
      return "proxy does not support the CONNECT command";
    case 0x08:
      return "proxy does not support the requested address type";
    default:
      return `proxy rejected CONNECT with reply code ${reply}`;
  }
}

async function negotiate(
  reader: ByteReader,
  write: (chunk: Uint8Array) => Promise<void>,
  credentials?: Socks5Credentials,
): Promise<void> {
  await write(buildGreeting(Boolean(credentials)));
  await reader.need(2, "method negotiation");

  const [version, method] = reader.take(2);
  if (version !== 0x05) {
    throw new Socks5Error(
      "socks5_protocol_error",
      `proxy replied with unsupported SOCKS version ${version}`,
    );
  }

  if (method === AUTH_NO_ACCEPTABLE) {
    throw new Socks5Error(
      "socks5_no_acceptable_method",
      "proxy accepted none of the offered authentication methods",
    );
  }

  if (method === AUTH_NONE) {
    return;
  }

  if (method !== AUTH_USERPASS) {
    throw new Socks5Error(
      "socks5_protocol_error",
      `proxy selected unsupported authentication method ${method}`,
    );
  }

  if (!credentials) {
    throw new Socks5Error(
      "socks5_auth_required",
      "proxy requires username/password authentication but none is configured",
    );
  }

  await write(buildAuth(credentials));
  await reader.need(2, "username/password authentication");
  const [, status] = reader.take(2);
  if (status !== 0x00) {
    // No credential material in this message, by design.
    throw new Socks5Error(
      "socks5_auth_failed",
      "proxy rejected the configured credentials",
    );
  }
}

async function readConnectReply(reader: ByteReader): Promise<void> {
  await reader.need(4, "CONNECT reply");
  const [version, reply, , addressType] = reader.take(4);

  if (version !== 0x05) {
    throw new Socks5Error(
      "socks5_protocol_error",
      `proxy replied with unsupported SOCKS version ${version}`,
    );
  }
  if (reply !== 0x00) {
    throw new Socks5Error("socks5_connect_failed", connectFailureMessage(reply));
  }

  // Consume the bound address so the buffer is positioned exactly at the first
  // tunnel byte. Everything below is served from the rolling buffer first.
  if (addressType === ATYP_IPV4) {
    await reader.need(6, "CONNECT bound address");
    reader.take(6);
    return;
  }
  if (addressType === ATYP_IPV6) {
    await reader.need(18, "CONNECT bound address");
    reader.take(18);
    return;
  }
  if (addressType === ATYP_DOMAIN) {
    await reader.need(1, "CONNECT bound address length");
    const [length] = reader.take(1);
    await reader.need(length + 2, "CONNECT bound address");
    reader.take(length + 2);
    return;
  }

  throw new Socks5Error(
    "socks5_protocol_error",
    `proxy replied with unsupported address type ${addressType}`,
  );
}

/**
 * Performs a SOCKS5 handshake on an already-connected socket and leaves it
 * positioned at the start of the tunnel.
 *
 * Throws {@link Socks5Error} on any failure so callers can fail closed instead
 * of falling back to a different egress path.
 */
export async function socks5Connect(
  socket: Socks5Socket,
  target: Socks5Target,
  credentials?: Socks5Credentials,
): Promise<Socks5Result> {
  // Validate before touching the socket: a malformed target must never put
  // bytes on the wire.
  const host = assertTarget(target);

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const buffered = new ByteReader(reader);
  const write = (chunk: Uint8Array) => writer.write(chunk);

  try {
    await negotiate(buffered, write, credentials);
    await write(buildConnect(host, target.port));
    await readConnectReply(buffered);
    return { leftover: buffered.rest };
  } finally {
    // Safe because every read above is awaited: no read promise is outstanding.
    reader.releaseLock();
    writer.releaseLock();
  }
}
