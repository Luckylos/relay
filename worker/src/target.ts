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
export function parseTarget(request: Request): TargetRequest {
  const incoming = new URL(request.url);
  const rawPathname = incoming.pathname;
  const firstSlash = rawPathname.indexOf("/", 1);
  const hostname = rawPathname.slice(1, firstSlash === -1 ? undefined : firstSlash);

  if (!hostname || !isValidHostname(hostname)) {
    throw new TargetError("invalid target hostname");
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
