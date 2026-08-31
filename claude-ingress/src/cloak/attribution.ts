/**
 * Claude Code billing attribution.
 *
 * Real Claude Code opens its `system` array with one metadata line:
 *
 *   x-anthropic-billing-header: cc_version=2.1.239.1c8; cc_entrypoint=cli;
 *
 * The three characters after the version are a build fingerprint the client
 * computes from its own request. Upstreams that admit only Claude Code clients
 * look for exactly this block, so a request without it is refused before any
 * model is reached -- observed directly as
 * `503 this group only allows Claude Code clients` on a request whose headers,
 * user-agent and `metadata.user_id` were already correct.
 *
 * This is the one piece of body content this cloak synthesizes, and it is worth
 * separating from the content it deliberately does *not* synthesize. The Claude
 * Code identity sentence ("You are Claude Code, Anthropic's official CLI for
 * Claude.") is an instruction: it changes what the model answers, which is why
 * body.ts still refuses to add it. This block is not an instruction. It carries
 * no directive a model can follow, and a probe carrying the block *without* the
 * identity sentence was admitted and answered normally, so the sentence buys
 * nothing here that would justify altering the caller's prompt semantics.
 *
 * Position is the head of `system`, matching the real client. That looks like it
 * should cost the caller its cached prefix, and it would if the block varied per
 * request -- but it does not. The fingerprint reads the *first* user message, so
 * every turn of one conversation produces the same block, and the prefix is
 * stable exactly where a real client's is. Taking the last user message instead
 * would recompute it on every turn and invalidate the prefix each time; that is
 * why this follows the first-message reading.
 */
import { sha256Hex } from "./hash";
import { isObject } from "./json";

/**
 * Salt for the build fingerprint.
 *
 * Recovered independently from two upstream implementations of this same
 * mimicry, which agree on the value; both trace it to captured client traffic.
 * The constant is load-bearing -- a different salt yields a fingerprint that
 * matches no real build.
 */
const FINGERPRINT_SALT = "59cf53e54c78";

/** Lower-cased on purpose: the upstream prefix test is case-sensitive. */
const ATTRIBUTION_PREFIX = "x-anthropic-billing-header:";

/**
 * The character offsets the client samples from the first user message.
 *
 * Read as UTF-16 code units, because the client is JavaScript and `text[i]` is
 * a code unit there. Both reference implementations of this algorithm are Go and
 * index by byte or by rune instead; all three agree on ASCII and diverge on
 * anything else, so matching the client's own semantics is what keeps the
 * fingerprint right for a non-ASCII prompt.
 */
const FINGERPRINT_INDICES: readonly number[] = [4, 7, 20];

/** Substituted for an offset past the end of the message. */
const MISSING_CHARACTER = "0";

/**
 * The first user message's leading text.
 *
 * The *first* rather than the latest: that is what makes the fingerprint stable
 * across the turns of one conversation. A first user message carrying no text
 * block at all (an image-only opener) yields the empty string rather than
 * falling through to a later message, so the value stays a property of the
 * conversation's opening.
 */
export function extractFirstUserText(messages: unknown): string {
  if (!Array.isArray(messages)) {
    return "";
  }

  for (const message of messages) {
    if (!isObject(message) || message.role !== "user") {
      continue;
    }

    const content = message.content;
    if (typeof content === "string") {
      return content;
    }

    if (Array.isArray(content)) {
      for (const block of content) {
        if (isObject(block) && block.type === "text" && typeof block.text === "string") {
          return block.text;
        }
      }
    }

    return "";
  }

  return "";
}

/**
 * `SHA-256(salt + sampled characters + version)`, first three hex digits.
 */
export async function computeFingerprint(
  messageText: string,
  cliVersion: string,
): Promise<string> {
  let sampled = "";
  for (const index of FINGERPRINT_INDICES) {
    sampled += messageText[index] ?? MISSING_CHARACTER;
  }

  return (await sha256Hex(FINGERPRINT_SALT + sampled + cliVersion)).slice(0, 3);
}

/**
 * Build the attribution line for a request.
 *
 * `cch=` is deliberately absent. Current clients no longer send it, so adding it
 * would make this request diverge from real traffic in the one direction that is
 * easy to notice.
 */
export async function buildAttributionText(
  messages: unknown,
  cliVersion: string,
  entrypoint: string,
): Promise<string> {
  const fingerprint = await computeFingerprint(
    extractFirstUserText(messages),
    cliVersion,
  );

  return `${ATTRIBUTION_PREFIX} cc_version=${cliVersion}.${fingerprint}; cc_entrypoint=${entrypoint};`;
}

/**
 * Whether a system block is an attribution line.
 *
 * Leading whitespace is tolerated here but never produced. Detection is the
 * liberal side of the transform -- it exists to recognise a block already in
 * place, including one a caller sent -- while emission stays exact.
 */
export function isAttributionText(value: unknown): boolean {
  return typeof value === "string" && value.trimStart().startsWith(ATTRIBUTION_PREFIX);
}

/**
 * The caller's `system`, as an array this module can prepend to.
 *
 * A string `system` is promoted to a one-element text block because the upstream
 * check only reads the array form, and the two are equivalent to the API. An
 * empty or whitespace-only string carries nothing and is dropped rather than
 * promoted into an empty block.
 */
function normalizeSystem(system: unknown): unknown[] {
  if (system === undefined || system === null) {
    return [];
  }

  if (typeof system === "string") {
    return system.trim() === "" ? [] : [{ type: "text", text: system }];
  }

  if (Array.isArray(system)) {
    return [...system];
  }

  // An unrecognised shape is left for the caller to own; wrapping it would
  // invent a schema.
  return [system];
}

/**
 * Put the attribution block at the head of `system`, replacing any already
 * there.
 *
 * Delete-then-write, matching how headers.ts treats the identity set: a caller
 * that already sent an attribution line sent one describing *its* build, and
 * keeping both would present two clients. Stripping first is also what makes the
 * transform idempotent, since the block this pass writes is the block the next
 * pass removes and rewrites identically.
 */
export function applyAttribution(system: unknown, attribution: string): unknown[] {
  const blocks = normalizeSystem(system).filter(
    (block) => !(isObject(block) && isAttributionText(block.text)),
  );

  return [{ type: "text", text: attribution }, ...blocks];
}
