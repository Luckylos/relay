export interface TargetRequest {
  hostname: string;
  pathname: string;
  search: string;
  url: URL;
}

export class TargetError extends Error {
  readonly code = "invalid_target" as const;

  constructor(message = "invalid target") {
    super(message);
    this.name = "TargetError";
  }
}

export interface TargetEnv {
  /**
   * Optional comma-separated upstream hostname allowlist.
   *
   * This Worker has no ingress gate, so without an allowlist it is an open
   * proxy to any public HTTPS host, egressing from the relay's VPS address.
   * Abuse would be attributed to that address, so restricting *which upstreams*
   * are reachable is what keeps an open endpoint safe -- it costs callers
   * nothing, since a caller only ever needs the hosts it actually uses.
   *
   * Unset or empty preserves the original any-public-host behaviour, so this can
   * be rolled back with a variable change and no redeploy of logic.
   *
   * Entries are matched case-insensitively against the exact hostname. A leading
   * dot (`.example.com`) additionally matches subdomains. No wildcards: `*` in a
   * hostname pattern is the classic source of accidental over-matching.
   */
  ALLOWED_UPSTREAM_HOSTS?: string;
}

const MAX_HOSTNAME_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
const LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/**
 * Dotted-quad shapes, i.e. anything whose final label is all digits.
 *
 * The target contract is "any public HTTPS hostname", never "any IP". The relay's
 * SSRF policy already rejects private and special-use addresses after DNS, but
 * accepting literals here would mean a caller could aim the relay at an arbitrary
 * address and rely on that single downstream check. Matching the Rust
 * `relay_target.rs` rule keeps both ends of the contract identical, and a
 * digits-only TLD is not a valid DNS name anyway.
 */
const NUMERIC_TLD_PATTERN = /^\d+$/;

/**
 * Names that resolve to the local host by convention rather than by address.
 *
 * `localhost` passes every syntactic hostname rule, so it needs an explicit
 * refusal to stay out of the target space.
 */
const FORBIDDEN_HOSTNAMES: ReadonlySet<string> = new Set(["localhost"]);

/**
 * Parse the allowlist into exact names and subdomain suffixes.
 *
 * Returns `null` when no allowlist is configured, which callers must treat as
 * "any valid public hostname" rather than as "deny all" -- an empty variable is
 * the documented opt-out, not a lockout.
 */
function parseAllowedHosts(
  raw: string | undefined,
): { exact: ReadonlySet<string>; suffixes: readonly string[] } | null {
  if (raw === undefined) {
    return null;
  }

  const exact = new Set<string>();
  const suffixes: string[] = [];
  for (const entry of raw.split(",")) {
    // Trailing dots are stripped so `example.com.` and `example.com` cannot
    // become two different allowlist identities.
    const trimmed = entry.trim().toLowerCase().replace(/\.$/, "");
    if (trimmed.length === 0) {
      continue;
    }
    if (trimmed.startsWith(".")) {
      const parent = trimmed.slice(1);
      if (parent.length > 0) {
        // `.example.com` covers the parent as well as its subdomains, which is
        // what an operator writing a domain-wide entry means.
        suffixes.push(trimmed);
        exact.add(parent);
      }
      continue;
    }
    exact.add(trimmed);
  }

  return exact.size === 0 && suffixes.length === 0 ? null : { exact, suffixes };
}

/**
 * True when `hostname` is permitted by the configured allowlist.
 *
 * Exported so redirect rewriting enforces the same restriction: an upstream must
 * not be able to redirect a client to a host the client could not have requested.
 */
export function isAllowedUpstreamHost(hostname: string, env: TargetEnv): boolean {
  const allowed = parseAllowedHosts(env.ALLOWED_UPSTREAM_HOSTS);
  if (allowed === null) {
    return true;
  }

  const candidate = hostname.toLowerCase().replace(/\.$/, "");
  if (allowed.exact.has(candidate)) {
    return true;
  }
  // endsWith on a dot-prefixed suffix cannot match a sibling domain: `.foo.com`
  // matches `a.foo.com` but never `evilfoo.com`.
  return allowed.suffixes.some((suffix) => candidate.endsWith(suffix));
}

/**
 * Hostname rules for the dynamic target contract.
 *
 * Exported so redirect rewriting validates against exactly the same rules as
 * inbound target parsing: a `Location` that could not have been requested
 * directly must not become reachable by way of a redirect.
 */
export function isValidHostname(hostname: string): boolean {
  if (
    hostname.length === 0 ||
    hostname.length > MAX_HOSTNAME_LENGTH ||
    hostname.includes("%")
  ) {
    return false;
  }

  const withoutTrailingDot = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  if (withoutTrailingDot.length === 0) {
    return false;
  }

  if (FORBIDDEN_HOSTNAMES.has(withoutTrailingDot.toLowerCase())) {
    return false;
  }

  const labels = withoutTrailingDot.split(".");
  // Rejects IPv4 literals and any other numeric-TLD form. Bracketed IPv6 is
  // already rejected by the label pattern, which forbids `[`, `]` and `:`.
  if (NUMERIC_TLD_PATTERN.test(labels[labels.length - 1] ?? "")) {
    return false;
  }

  return labels.every(
    (label) => label.length <= MAX_LABEL_LENGTH && LABEL_PATTERN.test(label),
  );
}

/**
 * Convert /<hostname>/<remaining-path>?<query> to an HTTPS target.
 *
 * The first raw path segment is intentionally validated before URL parsing so
 * encoded separators, schemes, credentials, and ports cannot change the
 * routing boundary.
 */
export function parseTarget(request: Request, env: TargetEnv = {}): TargetRequest {
  const incoming = new URL(request.url);
  const rawPathname = incoming.pathname;
  const firstSlash = rawPathname.indexOf("/", 1);
  const hostname = rawPathname.slice(1, firstSlash === -1 ? undefined : firstSlash);

  if (!hostname || !isValidHostname(hostname)) {
    throw new TargetError("invalid target hostname");
  }

  if (!isAllowedUpstreamHost(hostname, env)) {
    throw new TargetError("target hostname is not allowed");
  }

  const pathname = firstSlash === -1 ? "/" : rawPathname.slice(firstSlash);
  const url = new URL(`https://${hostname}${pathname}${incoming.search}`);

  if (url.protocol !== "https:" || url.port !== "" || url.hostname !== hostname.toLowerCase()) {
    throw new TargetError("invalid target URL");
  }

  return {
    hostname: url.hostname,
    pathname: url.pathname,
    search: url.search,
    url,
  };
}
