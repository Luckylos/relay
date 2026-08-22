/**
 * Request-body shaping.
 *
 * Two rules govern everything here.
 *
 * The first is that a transform must be idempotent:
 *
 *     transform(transform(body)) === transform(body)
 *
 * A request can traverse more than one hop of this Worker, and a non-idempotent
 * transform would stack a second identity block, a second date reminder and a
 * second cache breakpoint on each pass -- growing the prompt and invalidating
 * the cached prefix that the breakpoints exist to protect. Every insertion below
 * is therefore guarded by a check for what it is about to insert.
 *
 * The second is that the body is the source of truth for the beta header. The
 * capabilities reported here are read from the *transformed* body, so a beta can
 * never be announced without the field it describes, in either direction.
 */
import { CLAUDE_CODE_SYSTEM_IDENTITY } from "./profile";
import type { ClaudeEndpoint, RequestCapabilities } from "./beta";
import { buildUserId, type ClientIdentity } from "./identity";

/** Marker identifying a date reminder this module already inserted. */
const CURRENT_DATE_MARKER = "# currentDate";

/**
 * The reminder block, whitespace included.
 *
 * The trailing indentation is reproduced from the real template rather than
 * tidied: the text is part of the prompt, so normalizing it would change the
 * bytes that get hashed for prompt caching.
 */
function currentDateReminder(today: string): string {
  return `<system-reminder>
As you answer the user's questions, you can use the following context:
# currentDate
Today's date is ${today}.

      IMPORTANT: this context may or may not be relevant to your tasks. You should not respond to this context unless it is highly relevant to your task.
</system-reminder>`;
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Normalize `system` to block form.
 *
 * The API accepts a bare string, but cache control attaches to a block, so the
 * array form is the only one that can carry a breakpoint.
 */
function toSystemBlocks(system: unknown): JsonObject[] {
  if (typeof system === "string") {
    return system.length === 0 ? [] : [{ type: "text", text: system }];
  }
  if (Array.isArray(system)) {
    return system.filter(isObject);
  }
  return [];
}

function blockText(block: JsonObject): string {
  return typeof block.text === "string" ? block.text : "";
}

/**
 * Attach a cache breakpoint to the last element, if it is not already marked.
 *
 * Applied to the last block because a breakpoint caches everything *up to and
 * including* itself: on an earlier block it would leave the remainder of the
 * prefix uncached on every request.
 */
function markCacheBreakpoint(blocks: JsonObject[]): void {
  const last = blocks[blocks.length - 1];
  if (last === undefined || last.cache_control !== undefined) {
    return;
  }
  last.cache_control = { type: "ephemeral" };
}

export interface BodyTransformResult {
  readonly body: Uint8Array;
  readonly capabilities: RequestCapabilities;
}

/**
 * Capabilities of a body that could not be shaped.
 *
 * A non-JSON body, an unparseable one, or a non-`messages` endpoint still needs
 * a beta header derived from *something*. Reporting every capability as absent
 * keeps the header consistent with a body this module did not touch, rather than
 * announcing features that may not be there.
 */
function inertCapabilities(model: string): RequestCapabilities {
  return {
    model,
    hasTools: false,
    hasMcpServers: false,
    hasThinking: false,
    thinkingDisplay: false,
    hasContextManagement: false,
    hasStructuredOutput: false,
    hasEffort: false,
    fastMode: false,
  };
}

function readCapabilities(body: JsonObject): RequestCapabilities {
  const thinking = isObject(body.thinking) ? body.thinking : undefined;
  return {
    model: typeof body.model === "string" ? body.model : "",
    hasTools: Array.isArray(body.tools) && body.tools.length > 0,
    hasMcpServers: Array.isArray(body.mcp_servers) && body.mcp_servers.length > 0,
    hasThinking: thinking?.type === "enabled",
    // A display surface means the blocks are meant to come back visible, which
    // is what suppresses the redaction beta in beta.ts.
    thinkingDisplay: thinking !== undefined && thinking.display !== undefined,
    hasContextManagement: isObject(body.context_management),
    hasStructuredOutput:
      isObject(body.output_format) || isObject(body.response_format),
    hasEffort: body.effort !== undefined || body.per_message_effort !== undefined,
    fastMode: body.speed === "fast",
  };
}

export interface BodyTransformOptions {
  readonly endpoint: ClaudeEndpoint;
  readonly identity: ClientIdentity;
  readonly contentType: string | null;
  /** Injected so tests pin the date instead of racing the clock. */
  readonly today: string;
}

/**
 * Shape the body and report what it asks for.
 *
 * Anything that is not a JSON object is returned byte-for-byte. Re-encoding a
 * body this module does not understand risks corrupting it, and a body with no
 * recognisable shape has nothing to shape.
 */
export function transformBody(
  raw: Uint8Array,
  options: BodyTransformOptions,
): BodyTransformResult {
  if (!options.contentType?.toLowerCase().includes("application/json")) {
    return { body: raw, capabilities: inertCapabilities("") };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return { body: raw, capabilities: inertCapabilities("") };
  }

  if (!isObject(parsed)) {
    return { body: raw, capabilities: inertCapabilities("") };
  }

  const body = parsed;
  const model = typeof body.model === "string" ? body.model : "";

  // Only the two endpoints whose shape is known. `messages` and `count_tokens`
  // share the system/tools/metadata surface; anything else may be a body this
  // module would corrupt by rewriting.
  if (options.endpoint === "other") {
    return { body: raw, capabilities: inertCapabilities(model) };
  }

  const blocks = toSystemBlocks(body.system);

  // Identity first, and only if absent -- this is the idempotency guard for the
  // system prompt.
  if (!blocks.some((block) => blockText(block) === CLAUDE_CODE_SYSTEM_IDENTITY)) {
    blocks.unshift({ type: "text", text: CLAUDE_CODE_SYSTEM_IDENTITY });
  }

  if (!blocks.some((block) => blockText(block).includes(CURRENT_DATE_MARKER))) {
    blocks.push({ type: "text", text: currentDateReminder(options.today) });
  }

  body.system = blocks;

  const thinking = isObject(body.thinking) ? body.thinking : undefined;
  const hasThinking = thinking?.type === "enabled";

  // Conditional on thinking, matching the real builder: the edit clears thinking
  // blocks, so on a request without any it would describe work that cannot
  // happen. Never overwritten, because a caller's own edits are more specific
  // than this default.
  if (hasThinking && body.context_management === undefined) {
    body.context_management = {
      edits: [{ type: "clear_thinking_20251015", keep: "all" }],
    };
  }

  // Breakpoint on the system prefix, or on tools when there is no system.
  //
  // The tools fallback matters for stateless callers: a large tool definition
  // block with no breakpoint anywhere is re-tokenized on every request. Both are
  // no-ops when a breakpoint is already present, which is what keeps a second
  // pass from adding another one.
  if (blocks.length > 0) {
    markCacheBreakpoint(blocks);
  } else if (Array.isArray(body.tools)) {
    const tools = body.tools.filter(isObject);
    if (tools.length > 0) {
      markCacheBreakpoint(tools);
    }
  }

  const metadata = isObject(body.metadata) ? body.metadata : {};
  metadata.user_id = buildUserId(options.identity, metadata.user_id);
  body.metadata = metadata;

  return {
    body: new TextEncoder().encode(JSON.stringify(body)),
    // Read back from the transformed body, so the beta header describes what is
    // actually being sent rather than what arrived.
    capabilities: readCapabilities(body),
  };
}
