/**
 * SHA-256 hex digest.
 *
 * Shared by the two derivations that need one: the device/session identifiers
 * and the attribution build fingerprint. The output contract is load-bearing
 * rather than cosmetic -- both callers read fixed-width lowercase hex, so
 * `padStart` is what keeps a byte below 0x10 two characters wide. A second copy
 * that dropped it would not fail; it would silently shorten a derived value.
 */
const encoder = new TextEncoder();

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
