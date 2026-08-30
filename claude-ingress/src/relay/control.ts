/**
 * Relay control namespaces and parsed response attribution.
 *
 * The relay and Workers deploy independently, so both generations remain
 * reserved and readable. This module is the single owner of those namespaces:
 * request/response projection imports its prefix predicate, while response
 * attribution imports its parsed value. Current headers always take precedence;
 * an explicitly blank current value normalizes to null rather than trusting a
 * possibly forged legacy value.
 */
export const RELAY_CONTROL_PREFIX = "x-egress-relay-";
export const LEGACY_RELAY_CONTROL_PREFIX = "x-codex-relay-";

const RELAY_CONTROL_PREFIXES = [
  RELAY_CONTROL_PREFIX,
  LEGACY_RELAY_CONTROL_PREFIX,
] as const;

const RESULT_HEADERS = relayHeaderNames("result");
const ERROR_HEADERS = relayHeaderNames("error");
const REQUEST_ID_HEADERS = relayHeaderNames("request-id");
const CF_RAY_HEADERS = ["cf-ray"] as const;

export interface RelayResponseAttribution {
  readonly result: string | null;
  readonly error: string | null;
  readonly requestId: string | null;
  readonly cfRay: string | null;
}

function relayHeaderNames(field: string): readonly string[] {
  return RELAY_CONTROL_PREFIXES.map((prefix) => `${prefix}${field}`);
}

function readHeader(
  headers: Headers,
  names: readonly string[],
  normalize: (value: string) => string = (value) => value,
): string | null {
  for (const name of names) {
    const raw = headers.get(name);
    if (raw !== null) {
      const value = raw.trim();
      return value ? normalize(value) : null;
    }
  }
  return null;
}

/** True for a control header in either generation's namespace. */
export function isRelayControlHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return RELAY_CONTROL_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

export function readRelayResponseAttribution(
  headers: Headers,
): RelayResponseAttribution {
  const lowercase = (value: string): string => value.toLowerCase();
  return {
    result: readHeader(headers, RESULT_HEADERS, lowercase),
    error: readHeader(headers, ERROR_HEADERS, lowercase),
    requestId: readHeader(headers, REQUEST_ID_HEADERS),
    cfRay: readHeader(headers, CF_RAY_HEADERS),
  };
}
