/**
 * The single place where the Worker touches `cloudflare:sockets`.
 *
 * Keeping the platform import behind one function lets the egress layer be
 * exercised against an in-memory socket without a real TCP connection, and
 * keeps the runtime-specific types from leaking through the codebase.
 */
import { connect } from "cloudflare:sockets";

export interface TunnelSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  /**
   * Upgrades the connection in place. Only valid when the socket was opened
   * with `secureTransport: "starttls"`, which is how proxy tunnels are dialled:
   * the SOCKS5 handshake happens in the clear, TLS starts afterwards.
   */
  startTls(options: { expectedServerHostname: string }): {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  };
  close(): void | Promise<void>;
}

export type SocketFactory = (
  address: { hostname: string; port: number },
  options: { secureTransport: "starttls"; allowHalfOpen: boolean },
) => TunnelSocket;

export const connectSocket: SocketFactory = (address, options) =>
  connect(address, options) as unknown as TunnelSocket;
