/**
 * Client → Worker ingress authentication.
 *
 * This is deliberately a separate secret from the Worker → relay HMAC key: the
 * ingress token authenticates *callers of this Worker*, while the HMAC key proves
 * to the relay that a forward request came from the Worker. Reusing one value for
 * both would mean any authorized client could also forge relay envelopes.
 */

/** Header consumed by the Worker. Never projected onward. */
export const INGRESS_TOKEN_HEADER = "x-codex-relay-token";

/**
 * A 32-byte random token is 43 unpadded base64url characters. Anything shorter is
 * treated as misconfiguration rather than as a weak-but-usable credential, so a
 * placeholder value can never silently become the production gate.
 */
export const MIN_TOKEN_LENGTH = 43;

export interface IngressEnv {
  /** Worker secret. Must be >= 32 random bytes. */
  INGRESS_AUTH_TOKEN?: string;
}

export type IngressAuthResult =
  | { outcome: "authorized" }
  | { outcome: "unauthorized" }
  | { outcome: "misconfigured" };

/**
 * Length-independent equality.
 *
 * Comparing UTF-16 code units of equal-length strings takes the same number of
 * iterations regardless of where they first differ, so a caller cannot learn the
 * token prefix from response timing. Unequal lengths are folded into the same
 * loop to avoid an early return that would leak the expected length.
 */
function constantTimeEquals(a: string, b: string): boolean {
  const length = Math.max(a.length, b.length);
  let difference = a.length ^ b.length;
  for (let index = 0; index < length; index += 1) {
    // charCodeAt past the end yields NaN, so read a fixed sentinel instead to
    // keep the XOR meaningful for every iteration.
    const left = index < a.length ? a.charCodeAt(index) : 0;
    const right = index < b.length ? b.charCodeAt(index) : 0;
    difference |= left ^ right;
  }
  return difference === 0;
}

/**
 * Authenticate an inbound request.
 *
 * Callers must run this before target parsing, body reads and any egress, so that
 * an unauthenticated caller learns nothing about target validity or relay state.
 */
export function authenticateIngress(headers: Headers, env: IngressEnv): IngressAuthResult {
  const expected = env.INGRESS_AUTH_TOKEN;
  if (!expected || expected.length < MIN_TOKEN_LENGTH) {
    return { outcome: "misconfigured" };
  }

  const presented = headers.get(INGRESS_TOKEN_HEADER);
  if (presented === null || presented.length === 0) {
    return { outcome: "unauthorized" };
  }

  return constantTimeEquals(presented, expected)
    ? { outcome: "authorized" }
    : { outcome: "unauthorized" };
}
