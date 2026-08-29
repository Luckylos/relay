/**
 * `anthropic-beta` assembly.
 *
 * The native binary registers its beta features through a frozen
 * `{name, header}` registry, then builds the per-request list from the model and
 * the request's own capabilities before serializing with `Array#toString()`.
 * Three properties of that pipeline drive this implementation:
 *
 *  - the registry is a *lookup table*, not the header. 2.1.239 registers 32
 *    entries and sends a handful. Sending all 32 would be unlike any real
 *    client, and several entries are gated on providers or feature flags that do
 *    not apply here;
 *  - the list is derived from the request, so a beta must never be announced
 *    without the body feature it describes. A mismatch is both a fingerprint and
 *    a source of upstream 400s;
 *  - serialization is a plain comma join with no space, because `toString()` on
 *    an array uses `,`. Emitting `, ` would be a one-byte tell.
 */

/**
 * Registry declaration order at CLI 2.1.239.
 *
 * Order is preserved because the real list is built by pushing onto an array
 * walked in this order, so it is observable. Entries this Worker never derives
 * are still listed: the order is only meaningful if it is complete, and a
 * caller-supplied value that *is* registered should sort into its real position
 * rather than being appended as though it were unknown.
 */
export const BETA_REGISTRY_ORDER: readonly string[] = [
  "claude-code-20250219",
  "oauth-2025-04-20",
  "interleaved-thinking-2025-05-14",
  "context-1m-2025-08-07",
  "context-management-2025-06-27",
  "structured-outputs-2025-12-15",
  "web-search-2025-03-05",
  "advanced-tool-use-2025-11-20",
  "tool-search-tool-2025-10-19",
  "effort-2025-11-24",
  "task-budgets-2026-03-13",
  "prompt-caching-scope-2026-01-05",
  "prompt-caching-evict-2026-05-12",
  "extended-cache-ttl-2025-04-11",
  "fast-mode-2026-02-01",
  "redact-thinking-2026-02-12",
  "thinking-token-count-2026-05-13",
  "afk-mode-2026-01-31",
  "advisor-tool-2026-03-01",
  "cache-diagnosis-2026-04-07",
  "context-hint-2026-04-09",
  "mcp-servers-2025-12-04",
  "files-api-2025-04-14",
  "environments-2025-11-01",
  "ccr-byoc-2025-07-29",
  "mid-conversation-system-2026-04-07",
  "per-turn-control-2026-07-01",
  "server-side-fallback-2026-06-01",
  "server-side-fallback-2026-07-01",
  "fallback-credit-2026-06-01",
  "x-cc-internal-mid-conv-cache-promotion",
  "x-cc-internal-mid-conv-cache-promotion-ok",
  "auto-mode-classifier-2026-07-16",
];

/**
 * Appended by the SDK's token-counting helper, not by the CLI's registry.
 *
 * It is therefore not part of `BETA_REGISTRY_ORDER` and lands after the
 * registry-ordered values, which is where the real append puts it.
 */
export const TOKEN_COUNTING_BETA = "token-counting-2024-11-01";

/**
 * The values this module owns: derived from the request on every pass, so a
 * caller-supplied copy is dropped before rebuilding.
 *
 * Everything outside this set is carried through untouched. That asymmetry is
 * deliberate. `oauth-2025-04-20` and `extended-cache-ttl-2025-04-11` are coupled
 * to the caller's own credential type, which this Worker does not model, so
 * dropping them could break a working OAuth request; and an unrecognised beta is
 * far more likely to be a feature newer than this file than an error worth
 * silently discarding.
 */
const MANAGED_BETAS: ReadonlySet<string> = new Set([
  "claude-code-20250219",
  "interleaved-thinking-2025-05-14",
  "context-management-2025-06-27",
  "structured-outputs-2025-12-15",
  "advanced-tool-use-2025-11-20",
  "effort-2025-11-24",
  "fast-mode-2026-02-01",
  "redact-thinking-2026-02-12",
  "thinking-token-count-2026-05-13",
  "mcp-servers-2025-12-04",
  TOKEN_COUNTING_BETA,
]);

const REGISTRY_RANK: ReadonlyMap<string, number> = new Map(
  BETA_REGISTRY_ORDER.map((header, index) => [header, index]),
);

/**
 * What the body actually asks for.
 *
 * Every field maps to one observable request feature; nothing is inferred from
 * the caller's own beta header, or the derivation would amplify whatever the
 * caller guessed instead of describing the request.
 */
export interface RequestCapabilities {
  readonly model: string;
  readonly hasTools: boolean;
  readonly hasMcpServers: boolean;
  readonly hasThinking: boolean;
  readonly thinkingDisplay: boolean;
  readonly hasContextManagement: boolean;
  readonly hasStructuredOutput: boolean;
  readonly hasEffort: boolean;
  readonly fastMode: boolean;
}

export type ClaudeEndpoint = "messages" | "count_tokens" | "other";

/**
 * Split a beta header into values.
 *
 * Tolerant of whitespace and empties because the value arrives from an arbitrary
 * caller; a malformed header should degrade to "no betas requested" rather than
 * produce an empty-string entry that would serialize as a stray comma.
 */
export function parseBetaHeader(raw: string | null | undefined): string[] {
  if (!raw) {
    return [];
  }
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * The betas this request's own contents justify.
 *
 * `claude-code-20250219` is suppressed for haiku models, matching the real
 * builder: it is pushed only when the model name does not contain `haiku`.
 */
function derivedBetas(
  capabilities: RequestCapabilities,
  endpoint: ClaudeEndpoint,
): string[] {
  const betas: string[] = [];
  const model = capabilities.model.toLowerCase();

  if (!model.includes("haiku")) {
    betas.push("claude-code-20250219");
  }

  if (capabilities.hasThinking) {
    betas.push("interleaved-thinking-2025-05-14");
    betas.push("thinking-token-count-2026-05-13");
    // The real client announces redaction only when it is *not* displaying
    // thinking; with a display surface attached the blocks are meant to come
    // back visible, so claiming redaction would contradict the request.
    if (!capabilities.thinkingDisplay) {
      betas.push("redact-thinking-2026-02-12");
    }
  }

  // Only when the body carries the edits. The beta is what makes the
  // `context_management` field legal, so the two are announced together or not
  // at all -- see body.ts, which adds the field on the same condition.
  if (capabilities.hasContextManagement) {
    betas.push("context-management-2025-06-27");
  }

  if (capabilities.hasStructuredOutput) {
    betas.push("structured-outputs-2025-12-15");
  }

  if (capabilities.hasTools) {
    betas.push("advanced-tool-use-2025-11-20");
  }

  if (capabilities.hasMcpServers) {
    betas.push("mcp-servers-2025-12-04");
  }

  if (capabilities.hasEffort) {
    betas.push("effort-2025-11-24");
  }

  if (capabilities.fastMode) {
    betas.push("fast-mode-2026-02-01");
  }

  // The token-counting endpoint gets its own value, appended by the SDK helper
  // rather than by the request builder. It is not part of the /v1/messages set,
  // so a shared list for both endpoints would be wrong in both directions.
  if (endpoint === "count_tokens") {
    betas.push(TOKEN_COUNTING_BETA);
  }

  return betas;
}

/**
 * Rebuild the header value, or `null` when there is nothing to send.
 *
 * Idempotent by construction rather than by inspection: managed values are
 * discarded from the caller's list and re-derived from the body, so running this
 * over its own output reproduces it exactly. That property is what makes it safe
 * for a request to traverse more than one hop of this Worker.
 */
export function buildBetaHeader(
  incoming: string | null | undefined,
  capabilities: RequestCapabilities,
  endpoint: ClaudeEndpoint,
): string | null {
  const carried = parseBetaHeader(incoming).filter((beta) => !MANAGED_BETAS.has(beta));
  const combined: string[] = [];
  const seen = new Set<string>();
  for (const beta of [...derivedBetas(capabilities, endpoint), ...carried]) {
    if (!seen.has(beta)) {
      seen.add(beta);
      combined.push(beta);
    }
  }

  if (combined.length === 0) {
    return null;
  }

  // Registered values sort into their declaration position; unregistered ones
  // keep the caller's relative order at the tail, which is where an appended
  // value would land in a real client.
  const registered = combined
    .filter((beta) => REGISTRY_RANK.has(beta))
    .sort((left, right) => REGISTRY_RANK.get(left)! - REGISTRY_RANK.get(right)!);
  const unregistered = combined.filter((beta) => !REGISTRY_RANK.has(beta));

  // Comma with no space: `Array#toString()` is the real serializer.
  return [...registered, ...unregistered].join(",");
}
