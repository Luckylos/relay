/**
 * Request-body handling.
 *
 * The body belongs to the caller and this module leaves it that way. `system`,
 * `tools`, `messages`, `thinking` and everything else are forwarded exactly as
 * received. The single exception is `metadata.user_id`, which carries the client
 * identity this cloak exists to present and contributes nothing to the prompt.
 *
 * Content is deliberately not synthesized. An earlier revision prepended the
 * Claude Code identity line, appended a `# currentDate` reminder, inserted a
 * `context_management` edit and planted cache breakpoints. Each was a mistake:
 *
 *   - A block unshifted onto the head of `system` shifts the entire prompt
 *     prefix, so the caller's own prompt cache misses -- and a reminder carrying
 *     today's date re-misses every midnight. The breakpoints added alongside it
 *     could not repair damage they were causing.
 *   - `clear_thinking_20251015` instructs the API to drop thinking blocks. On a
 *     multi-turn request that owns its thinking history that is silent data loss
 *     the caller never asked for.
 *   - An identity line and a date reminder change what the model answers. A
 *     relay that alters responses is not transparent, whatever its headers say.
 *
 * There is also no disguise to be had here. Real Claude Code sends a large
 * situated system prompt -- tool inventory, working directory, git state -- that
 * differs on every request. One fixed sentence does not approximate it; it
 * produces a request resembling neither a real client nor an honest API caller,
 * and bills the caller tokens for the confusion. The header and identity
 * envelope is where this cloak can be accurate, so that is where it stops.
 *
 * One rule survives: the beta header must describe the body. Capabilities are
 * read from the request as it will be sent, so a beta is never announced without
 * the field it names.
 */
import type { ClaudeEndpoint, RequestCapabilities } from "./beta";
import { buildUserId, type ClientIdentity } from "./identity";

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export interface BodyTransformResult {
  readonly body: Uint8Array;
  readonly capabilities: RequestCapabilities;
}

/**
 * Capabilities of a body that could not be read.
 *
 * A non-JSON body, an unparseable one, or an endpoint whose shape is unknown
 * still needs a beta header derived from something. Reporting every capability
 * as absent keeps the header consistent with a body this module cannot see into,
 * rather than announcing features that may not be there.
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
}

/**
 * Stamp the client identity and report what the body asks for.
 *
 * Anything that is not a JSON object is returned byte-for-byte: re-encoding a
 * body this module cannot parse risks corrupting a request that would otherwise
 * have worked, and there is no metadata field to write into.
 *
 * Idempotent by construction -- `buildUserId` returns the same value for the
 * same identity, so a second hop rewrites `metadata.user_id` to what it already
 * held and no other field is touched.
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

  // Only the two endpoints known to carry a `metadata` object. Writing the field
  // onto an unrecognised shape would be inventing a schema.
  if (options.endpoint === "other") {
    return { body: raw, capabilities: inertCapabilities(model) };
  }

  // Merged rather than replaced: a caller's other metadata keys are its own.
  const metadata = isObject(body.metadata) ? body.metadata : {};
  metadata.user_id = buildUserId(options.identity, metadata.user_id);
  body.metadata = metadata;

  return {
    body: new TextEncoder().encode(JSON.stringify(body)),
    capabilities: readCapabilities(body),
  };
}
