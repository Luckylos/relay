/**
 * Proxy egress: one request through a SOCKS5 tunnel with platform TLS.
 *
 *   connectSocket(proxy, starttls)
 *     -> SOCKS5 negotiation / RFC 1929 auth / CONNECT(upstream:443)
 *     -> startTls({ expectedServerHostname: upstream })
 *     -> HTTP/1.1 request, streamed response
 *
 * TLS is terminated by the runtime against the *upstream* hostname, so the proxy
 * operator sees only ciphertext and cannot substitute its own certificate.
 *
 * Every failure throws. Nothing in this module falls back to direct egress:
 * once a proxy is configured, bypassing it would silently expose the real
 * Worker egress IP, which is the whole reason the proxy exists.
 */
import { projectResponseHeaders } from "../headers";
import type { TargetRequest } from "../target";
import { buildRequest, readResponse } from "./http1";
import { connectSocket, type SocketFactory, type TunnelSocket } from "./sockets";
import { socks5Connect, type Socks5Credentials } from "./socks5";

export type ProxyConfigErrorCode =
  | "proxy_invalid_url"
  | "proxy_unsupported_scheme";

/**
 * Configuration failure. Messages never echo the supplied URL: `EGRESS_PROXY_URL`
 * carries proxy credentials in its userinfo, and this error reaches logs.
 */
export class ProxyConfigError extends Error {
  readonly code: ProxyConfigErrorCode;

  constructor(code: ProxyConfigErrorCode, message: string) {
    super(message);
    this.name = "ProxyConfigError";
    this.code = code;
  }
}

export type ProxyErrorCode =
  | "proxy_connect_failed"
  | "proxy_protocol_error"
  | "proxy_tls_failed"
  | "proxy_timeout";

/** Runtime tunnel failure. Always fatal: callers must not retry via direct egress. */
export class ProxyError extends Error {
  readonly code: ProxyErrorCode;

  constructor(code: ProxyErrorCode, message: string) {
    super(message);
    this.name = "ProxyError";
    this.code = code;
  }
}

export interface ProxyConfig {
  hostname: string;
  port: number;
  credentials?: Socks5Credentials;
}

/** Socket surface used by this module; see `./sockets`. */
export type ProxySocket = TunnelSocket;
export type ProxyConnect = SocketFactory;

const DEFAULT_SOCKS_PORT = 1080;
const UPSTREAM_TLS_PORT = 443;

/**
 * Guards the setup phase only — handshake, TLS and response head. The body
 * stream is deliberately excluded: an idle SSE stream is normal, and a deadline
 * there would truncate long completions.
 */
export const DEFAULT_TUNNEL_TIMEOUT_MS = 120_000;

/**
 * Parse `EGRESS_PROXY_URL`.
 *
 * `socks5h` is accepted as an alias: CONNECT always carries `ATYP=DOMAIN`, so
 * the proxy resolves the upstream name either way and no DNS leaks locally.
 */
export function parseProxyUrl(raw: string): ProxyConfig {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // Deliberately omits `raw` — it may contain credentials.
    throw new ProxyConfigError(
      "proxy_invalid_url",
      "proxy URL is not a valid URL",
    );
  }

  if (url.protocol !== "socks5:" && url.protocol !== "socks5h:") {
    throw new ProxyConfigError(
      "proxy_unsupported_scheme",
      `unsupported proxy scheme "${url.protocol.replace(":", "")}"; expected socks5 or socks5h`,
    );
  }

  const hostname = url.hostname;
  if (!hostname) {
    throw new ProxyConfigError(
      "proxy_invalid_url",
      "proxy URL is missing a hostname",
    );
  }

  const port = url.port === "" ? DEFAULT_SOCKS_PORT : Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ProxyConfigError(
      "proxy_invalid_url",
      "proxy URL port is out of range",
    );
  }

  let credentials: Socks5Credentials | undefined;
  if (url.username !== "") {
    // Userinfo is percent-encoded, so credentials containing @ : / survive.
    credentials = {
      username: safeDecode(url.username),
      password: safeDecode(url.password),
    };
  }

  return { hostname, port, credentials };
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export interface ProxyEgressRequest {
  target: TargetRequest;
  method: string;
  headers: Headers;
  body: Uint8Array;
  proxy: ProxyConfig;
  /** Setup deadline in milliseconds; defaults to {@link DEFAULT_TUNNEL_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** Injectable for tests; production uses `cloudflare:sockets`. */
  connect?: ProxyConnect;
}

export async function sendViaProxy(
  request: ProxyEgressRequest,
): Promise<Response> {
  const dial = request.connect ?? connectSocket;
  const { hostname, port } = request.proxy;

  let socket: ProxySocket;
  try {
    socket = dial(
      { hostname, port },
      { secureTransport: "starttls", allowHalfOpen: false },
    );
  } catch (error) {
    throw new ProxyError(
      "proxy_connect_failed",
      `could not open a socket to the configured proxy: ${reason(error)}`,
    );
  }

  const timeoutMs = request.timeoutMs ?? DEFAULT_TUNNEL_TIMEOUT_MS;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(
        new ProxyError(
          "proxy_timeout",
          `proxy tunnel did not deliver a response head within ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);
  });

  try {
    // Promise.race keeps a handler on both sides, so the loser's later
    // settlement can never surface as an unhandled rejection.
    return await Promise.race([establish(socket, request), deadline]);
  } catch (error) {
    // Free the tunnel on every failure path. On success the response stream
    // owns the socket and closing here would truncate the body.
    void closeQuietly(socket);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function establish(
  socket: ProxySocket,
  request: ProxyEgressRequest,
): Promise<Response> {
  const { leftover } = await socks5Connect(
    socket,
    { hostname: request.target.hostname, port: UPSTREAM_TLS_PORT },
    request.proxy.credentials,
  );

  // After the CONNECT reply every byte belongs to the TLS handshake, which the
  // platform owns — bytes already pulled off the socket cannot be pushed back.
  // A compliant proxy sends nothing before our ClientHello, so extra bytes mean
  // the stream is desynchronised and starting TLS would fail obscurely.
  if (leftover.byteLength > 0) {
    throw new ProxyError(
      "proxy_protocol_error",
      `proxy sent ${leftover.byteLength} unexpected byte(s) after the CONNECT reply`,
    );
  }

  let secure: {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  };
  try {
    // expectedServerHostname drives SNI *and* certificate/hostname validation.
    secure = socket.startTls({
      expectedServerHostname: request.target.hostname,
    });
  } catch (error) {
    throw new ProxyError(
      "proxy_tls_failed",
      `TLS handshake with the upstream failed: ${reason(error)}`,
    );
  }

  const writer = secure.writable.getWriter();
  try {
    await writer.write(
      buildRequest({
        method: request.method,
        target: `${request.target.pathname}${request.target.search}`,
        hostname: request.target.hostname,
        headers: request.headers,
        body: request.body,
      }),
    );
    if (request.body.byteLength > 0) {
      await writer.write(request.body);
    }
  } finally {
    // Released, not closed: closing the writer would half-close the tunnel
    // before the response arrives.
    writer.releaseLock();
  }

  const upstream = await readResponse(secure.readable);

  return new Response(upstream.body as BodyInit | null, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: projectResponseHeaders(upstream.headers),
  });
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}

async function closeQuietly(socket: ProxySocket): Promise<void> {
  try {
    await socket.close();
  } catch {
    // A socket that is already broken is exactly the state we wanted.
  }
}
