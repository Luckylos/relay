/**
 * Narrowing for parsed JSON.
 *
 * Both exclusions are load-bearing: `typeof null === "object"` and an array is
 * an object too, so a copy that forgot either would admit a value that the
 * callers go on to index by key. The request body shaping and the attribution
 * walk narrow the same parsed JSON, which is why this is one definition rather
 * than one per consumer.
 */
export type JsonObject = Record<string, unknown>;

export function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
