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
 *
 * Named entries here are the non-`cf-` ones plus the `cf-` headers worth
 * documenting; every `cf-` header is additionally stripped by prefix below, so
 * this list does not have to stay exhaustive.
 */
export const SOURCE_REVEALING_HEADERS = [
  "cdn-loop",
  "cf-connecting-ip",
  "cf-connecting-ipv6",
  "cf-ipcountry",
  "cf-pseudo-ipv4",
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

/**
 * Every Cloudflare-injected header, matched by prefix.
 *
 * A fixed list was not enough: `cf-pseudo-ipv4` reached a real upstream through
 * this Worker because it was added to the platform after the list was written.
 * Cloudflare can introduce a new `cf-` header at any time, and each one is a
 * client-describing value that defeats the relay's whole purpose, so the prefix
 * is the rule and the list above is only documentation. Nothing legitimate for
 * an upstream ever arrives under this prefix.
 */
export const CLOUDFLARE_HEADER_PREFIX = "cf-";

/**
 * Control headers are reserved for the relay envelope itself.
 *
 * Two prefixes, not one. The relay and both ingresses deploy independently, so
 * during the migration window both envelope generations are live on the wire.
 * Stripping only the current prefix would let an open caller forge
 * `x-codex-relay-result` and have this Worker's own attribution read believe
 * it. Both generations stay reserved permanently: dropping the legacy prefix
 * from the strip set is what reopens the forgery path, not what closes it.
 */
export const RELAY_CONTROL_PREFIX = "x-egress-relay-";
export const LEGACY_RELAY_CONTROL_PREFIX = "x-codex-relay-";

const RELAY_CONTROL_PREFIXES = [
  RELAY_CONTROL_PREFIX,
  LEGACY_RELAY_CONTROL_PREFIX,
] as const;

/** True for a control header in either generation's namespace. */
export function isRelayControlHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return RELAY_CONTROL_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

const STRIPPED_REQUEST_HEADERS: ReadonlySet<string> = new Set<string>([
  ...REQUEST_HOP_BY_HOP_HEADERS,
  ...SOURCE_REVEALING_HEADERS,
]);

/**
 * True when a client-supplied request header must not be forwarded upstream.
 *
 * The relay-control prefixes are matched rather than listed so that adding an
 * envelope field later cannot accidentally open a forgery path.
 *
 * This matters more, not less, now that the Worker has no ingress credential:
 * the prefix rule is the single mechanism keeping every client-supplied
 * control header -- in either generation's namespace -- out of the signed block
 * and off the wire, so an open caller cannot forge an envelope field or its
 * result attribution.
 */
export function isStrippedRequestHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    STRIPPED_REQUEST_HEADERS.has(lower) ||
    isRelayControlHeader(lower) ||
    lower.startsWith(CLOUDFLARE_HEADER_PREFIX)
  );
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
    if (isRelayControlHeader(name)) {
      continue;
    }
    output.set(name, value);
  }
  return output;
}
