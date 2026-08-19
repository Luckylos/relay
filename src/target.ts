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

function isValidHostname(hostname: string): boolean {
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

  return withoutTrailingDot.split(".").every(
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
