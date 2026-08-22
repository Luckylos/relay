export const RESPONSE_HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
] as const;

/**
 * Headers describing *this* hop's connection or framing. The relay re-frames the
 * request on its own connection, so forwarding them is meaningless and is
 * rejected by the relay's canonical-header validation.
 */
export const REQUEST_HOP_BY_HOP_HEADERS = [
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
] as const;

/**
 * Headers injected by Cloudflare (or any fronting proxy) that describe the
 * *client*, not the business request.
 *
 * The entire point of the relay is that upstream sees the VPS as the origin of
 * the request. Forwarding these would hand the upstream the real client IP and
 * the Cloudflare trace chain, defeating that property, so they are stripped even
 * though they are not hop-by-hop in the RFC sense.
 */
export const SOURCE_REVEALING_HEADERS = [
  "cdn-loop",
  "cf-connecting-ip",
  "cf-connecting-ipv6",
  "cf-ipcountry",
  "cf-ray",
  "cf-visitor",
  "cf-worker",
  "forwarded",
  "true-client-ip",
  "x-client-ip",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
] as const;

/** Control headers are reserved for the relay envelope itself. */
export const RELAY_CONTROL_PREFIX = "x-codex-relay-";

const STRIPPED_REQUEST_HEADERS: ReadonlySet<string> = new Set<string>([
  ...REQUEST_HOP_BY_HOP_HEADERS,
  ...SOURCE_REVEALING_HEADERS,
]);

/**
 * True when a client-supplied request header must not be forwarded upstream.
 *
 * The relay-control prefix is matched rather than listed so that adding an
 * envelope field later cannot accidentally open a forgery path.
 *
 * This matters more, not less, now that the Worker has no ingress credential:
 * the prefix rule is the single mechanism keeping every client-supplied
 * `x-codex-relay-*` header out of the signed block and off the wire, so an open
 * caller cannot forge an envelope field or its result attribution.
 */
export function isStrippedRequestHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return STRIPPED_REQUEST_HEADERS.has(lower) || lower.startsWith(RELAY_CONTROL_PREFIX);
}

export function projectResponseHeaders(incoming: Headers): Headers {
  const output = new Headers();
  for (const [name, value] of incoming) {
    if (
      RESPONSE_HOP_BY_HOP_HEADERS.includes(
        name as (typeof RESPONSE_HOP_BY_HOP_HEADERS)[number],
      )
    ) {
      continue;
    }
    // Relay control headers are an internal Worker<->relay channel, consumed by
    // the attribution step. Forwarding one would tell the client a relay exists
    // and hand it a correlation id it cannot use. Matched by prefix, not by a
    // fixed list, so a future control header cannot leak by being forgotten here.
    if (name.toLowerCase().startsWith(RELAY_CONTROL_PREFIX)) {
      continue;
    }
    output.set(name, value);
  }
  return output;
}
