/**
 * Deterministic client identity.
 *
 * A real client persists its identifiers to disk: the device id is 32 random
 * bytes hex-encoded once and reused, and the session id is generated per CLI
 * session and shared by every request in it. A Worker has neither disk nor
 * session affinity -- isolates are recycled, so in-memory state would produce a
 * new identity at unpredictable intervals.
 *
 * Deriving from the caller's own API key solves that without new infrastructure:
 * the same key always yields the same identity, different keys never collide,
 * and nothing is stored. Random-per-request was the alternative and it is
 * strictly worse -- it would present every single request as a brand-new device
 * and a brand-new session, which no real client does.
 *
 * The key is used as HMAC-style input only. It is hashed with a domain separator
 * and never logged, echoed, or included in the derived output, so the identifiers
 * cannot be walked back to the credential.
 */
import { sha256Hex } from "./hash";
import type { CloakProfile } from "./profile";

export interface ClientIdentity {
  /** 64 lowercase hex, matching the real 32-random-byte device id. */
  readonly deviceId: string;
  /** UUID-shaped, stable per key. */
  readonly sessionId: string;
  /**
   * Empty for API-key auth.
   *
   * This is not a missing value: the real client sends `""` when there is no
   * OAuth account attached, so inventing a UUID here would be *less* authentic
   * than the empty string and would assert a first-party account that does not
   * exist.
   */
  readonly accountUuid: "";
}

/**
 * Format 32 hex characters as a v4-shaped UUID.
 *
 * The version and variant nibbles are forced because a session id that fails
 * UUID validation is a stronger tell than one that is merely derived: the real
 * value is a v4 UUID, and consumers may well validate its shape.
 */
function asUuid(hex: string): string {
  const version = `4${hex.slice(13, 16)}`;
  // 0b10xx: the RFC 4122 variant bits.
  const variantNibble = ((parseInt(hex[16] ?? "0", 16) & 0x3) | 0x8).toString(16);
  const variant = `${variantNibble}${hex.slice(17, 20)}`;
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    version,
    variant,
    hex.slice(20, 32),
  ].join("-");
}

/**
 * Derive the identity for a caller.
 *
 * An absent API key still yields a usable identity, from the empty string. The
 * alternative -- failing the request -- would break OAuth-bearer callers, who
 * legitimately send no `x-api-key` at all.
 */
export async function deriveIdentity(
  apiKey: string | null,
  profile: CloakProfile,
): Promise<ClientIdentity> {
  // Distinct salts per field: one hash reused for both identifiers would make
  // the device id and session id trivially derivable from each other.
  const base = `${profile.identitySalt}\u0000${apiKey ?? ""}`;
  const [deviceId, sessionHex] = await Promise.all([
    sha256Hex(`${base}\u0000device`),
    sha256Hex(`${base}\u0000session`),
  ]);

  return {
    deviceId,
    sessionId: asUuid(sessionHex),
    accountUuid: "",
  };
}

/** Reserved metadata keys the real client refuses to let extra metadata shadow. */
const RESERVED_METADATA_KEYS: ReadonlySet<string> = new Set([
  "ti",
  "os",
  "sb",
  "he",
  "uf",
  "ap",
  "tk",
]);

/**
 * The real client's hard ceiling on the serialized `user_id`.
 *
 * On overflow it discards the extra fields and sends only the core three rather
 * than truncating, since a truncated JSON string would not parse.
 */
const MAX_USER_ID_LENGTH = 512;

/**
 * Build `metadata.user_id`.
 *
 * The value is a JSON *string*, not an object -- a nested object would be
 * immediately distinguishable from a real request. Key order is emission order:
 * device, account, session, then any surviving caller extras.
 *
 * Caller-supplied extras are preserved because they may carry legitimate
 * application context, but the three identity fields are always overwritten:
 * forwarding a real client's device or session id would put two different
 * machines behind one credential.
 */
export function buildUserId(identity: ClientIdentity, existing: unknown): string {
  const core: Record<string, unknown> = {
    device_id: identity.deviceId,
    account_uuid: identity.accountUuid,
    session_id: identity.sessionId,
  };

  const extras: Record<string, unknown> = {};
  if (typeof existing === "string") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(existing);
    } catch {
      parsed = null;
    }
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (key in core || RESERVED_METADATA_KEYS.has(key)) {
          continue;
        }
        // Scalars only, mirroring the real filter. An object or array here would
        // be dropped by a real client, so forwarding one is a tell.
        if (
          typeof value === "string" ||
          typeof value === "number" ||
          typeof value === "boolean"
        ) {
          extras[key] = value;
        }
      }
    }
  }

  const full = JSON.stringify({ ...extras, ...core });
  return full.length > MAX_USER_ID_LENGTH ? JSON.stringify(core) : full;
}
