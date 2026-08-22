import {
  isAllowedUpstreamHost,
  isValidHostname,
  parseTarget,
  type TargetEnv,
  type TargetRequest,
} from "./target";

/**
 * Upstream redirect rewriting.
 *
 * The relay never follows redirects (`Policy::none()` on the Rust side), so a 3xx
 * arrives here with the upstream's own `Location`. Handing that to the client
 * unchanged would defeat the entire architecture: a client that follows redirects
 * would connect to the upstream host directly, from its own IP, bypassing the
 * fixed VPS egress. Every accepted `Location` is therefore rewritten back onto
 * this Worker's dynamic-target form.
 */

export class RedirectError extends Error {
  readonly code = "invalid_upstream_redirect" as const;

  constructor(message = "invalid upstream redirect") {
    super(message);
    this.name = "RedirectError";
  }
}

/**
 * Characters that must never appear in a `Location` we act on.
 *
 * `new URL()` silently strips CR, LF and tabs rather than rejecting them, so a
 * header-splitting attempt like `https://h/v2\r\nX-Injected: 1` would otherwise
 * parse cleanly into a path of `/v2X-Injected:%201`. Rejecting before parsing
 * keeps that ambiguity out of the rewritten URL entirely.
 */
const FORBIDDEN_CHARACTERS = /[\r\n\t]/;

/**
 * Rewrite an upstream `Location` onto the Worker's own origin.
 *
 * @param location Raw `Location` header value from the upstream.
 * @param target The target the upstream request was sent to; used as the RFC 3986
 *   base so relative redirects resolve against the upstream, not the Worker.
 * @param workerUrl The inbound request URL, providing the origin to rewrite onto.
 * @param env Target configuration, so the upstream allowlist applies to
 *   redirects too.
 * @throws {RedirectError} When the redirect could not be expressed as a valid
 *   dynamic target, i.e. anything the client could not have requested directly.
 */
export function rewriteLocation(
  location: string,
  target: TargetRequest,
  workerUrl: URL,
  env: TargetEnv = {},
): string {
  if (FORBIDDEN_CHARACTERS.test(location)) {
    throw new RedirectError("redirect contains forbidden characters");
  }

  // An empty or whitespace-only Location resolves to the base URL, which would
  // send the client back to the same target and spin a redirect loop.
  if (location.trim().length === 0) {
    throw new RedirectError("redirect location is empty");
  }

  let resolved: URL;
  try {
    resolved = new URL(location, target.url);
  } catch {
    throw new RedirectError("redirect location is not a valid URL");
  }

  // Only plain HTTPS survives. http: would downgrade the upstream hop, and
  // opaque schemes (javascript:, data:, file:) are not upstream targets at all.
  if (resolved.protocol !== "https:") {
    throw new RedirectError("redirect must be https");
  }
  if (resolved.username.length > 0 || resolved.password.length > 0) {
    throw new RedirectError("redirect must not carry credentials");
  }
  // `URL` normalizes away the default `:443`, so a non-empty port here is always
  // an explicitly custom one. The target contract is "any public HTTPS hostname",
  // never "any port".
  if (resolved.port.length > 0) {
    throw new RedirectError("redirect must not specify a port");
  }
  // Same rules as inbound target parsing: this rejects IP literals (including
  // bracketed IPv6), underscores, bare dots and over-long labels, so a redirect
  // cannot reach a target that `parseTarget` would have refused.
  if (!isValidHostname(resolved.hostname)) {
    throw new RedirectError("redirect hostname is not a valid target");
  }
  // A redirect must not widen the target space: without this an upstream could
  // bounce a client to a host the allowlist forbids, and the Worker would
  // happily relay the follow-up request to it.
  if (!isAllowedUpstreamHost(resolved.hostname, env)) {
    throw new RedirectError("redirect hostname is not an allowed target");
  }

  // Built from the parsed parts rather than by string concatenation so the
  // hostname cannot inject extra path segments. `pathname` and `search` are kept
  // exactly as parsed, preserving percent-encoding such as %2F; `hash` is
  // dropped because fragments are never sent to a server.
  //
  // `hostname` is deliberate: `host` would carry a port, and while the check
  // above already rejects explicit ports, reading the port-free field keeps the
  // first path segment a bare hostname regardless of what that check allows
  // later. The dynamic-target route cannot express a port at all.
  const rewritten = new URL(workerUrl.toString());
  rewritten.pathname = `/${resolved.hostname}${resolved.pathname}`;
  rewritten.search = resolved.search;
  rewritten.hash = "";

  // The rewritten URL is what a client will send back to this Worker, so it must
  // be parseable as a dynamic target. Verifying here turns any future drift
  // between the two rule sets into a fail-closed error rather than a redirect the
  // Worker would reject on the next hop.
  try {
    parseTarget(new Request(rewritten.toString()), env);
  } catch {
    throw new RedirectError("rewritten redirect is not a valid target");
  }

  return rewritten.toString();
}
