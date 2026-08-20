/**
 * Fixed relay endpoint and shared signing key.
 *
 * All three are required. There is no default and no fallback: the relay is the
 * only egress path, so an incomplete configuration must fail the request.
 */
export interface RelayEnv {
  /** Absolute `https://` URL of the relay's `/v1/forward` endpoint. */
  EGRESS_RELAY_URL?: string;
  EGRESS_RELAY_KEY_ID?: string;
  /** Shared HMAC secret. Belongs in a Worker secret, never in vars. */
  EGRESS_RELAY_SECRET?: string;
}

export interface RelayConfig {
  url: string;
  keyId: string;
  secret: string;
}

export class RelayConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayConfigError";
  }
}

export function readRelayConfig(env: RelayEnv): RelayConfig {
  const url = env.EGRESS_RELAY_URL;
  const keyId = env.EGRESS_RELAY_KEY_ID;
  const secret = env.EGRESS_RELAY_SECRET;

  if (!url?.length || !keyId?.length || !secret?.length) {
    throw new RelayConfigError("relay egress is not configured");
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new RelayConfigError("relay URL is not a valid URL");
  }

  // Plaintext to the relay would expose the signed envelope, the business
  // Authorization header and the body to the path between Worker and VPS.
  if (parsed.protocol !== "https:") {
    throw new RelayConfigError("relay URL must be https");
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new RelayConfigError("relay URL must not carry credentials");
  }

  return { url: parsed.toString(), keyId, secret };
}
