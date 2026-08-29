/**
 * Request-body handling.
 *
 * The body belongs to the caller and stays that way, with two exceptions:
 * `metadata.user_id`, which carries the client identity this cloak presents, and
 * the billing attribution block at the head of `system`, which is what admits
 * the request to a Claude-Code-only upstream at all. `tools`, `messages`,
 * `thinking` and every other field are forwarded exactly as received.
 *
 * Where the line is drawn, and why there. An earlier revision also prepended the
 * Claude Code identity sentence, appended a `# currentDate` reminder and inserted
 * a `context_management` edit. Those stay out:
 *
 *   - The identity sentence and the date reminder are instructions. They change
 *     what the model answers, and a relay that alters answers is not transparent
 *     whatever its headers say. A probe carrying the attribution block *without*
 *     the sentence was admitted and answered normally, so the sentence buys no
 *     admission that would justify the cost.
 *   - `clear_thinking_20251015` instructs the API to drop thinking blocks. On a
 *     multi-turn request that owns its thinking history that is silent data loss
 *     the caller never asked for.
 *
 * The attribution block is a different kind of content: metadata rather than
 * instruction, carrying no directive a model can follow, and computed from the
 * request rather than invented. See attribution.ts for the fingerprint, and for
 * why placing it at the head does not cost the caller its cached prefix.
 *
 * It is applied unconditionally, with no caller-detection branch and no variable
 * to turn it off. The upstream check is all-or-nothing -- a request without the
 * block is refused before a model is reached -- so an off switch would only
 * describe a request this Worker cannot usefully send. Both reference
 * implementations of this mimicry gate it behind a per-credential flag because
 * they front arbitrary providers, some of which read the block as prose; this
 * Worker's callers point at a Claude upstream by construction.
 *
 * One rule survives unchanged: the beta header must describe the body.
 * Capabilities are read from the request as it will be sent, so a beta is never
 * announced without the field it names.
 */
import { applyAttribution, buildAttributionText } from "./attribution";
import type { ClaudeEndpoint, RequestCapabilities } from "./beta";
import { buildUserId, type ClientIdentity } from "./identity";
import type { CloakProfile } from "./profile";

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
  /** Supplies the CLI version and entrypoint the attribution block reports. */
  readonly profile: CloakProfile;
}

/**
 * Stamp the client identity and the attribution block, and report what the body
 * asks for.
 *
 * Anything that is not a JSON object is returned byte-for-byte: re-encoding a
 * body this module cannot parse risks corrupting a request that would otherwise
 * have worked, and there is no field to write into.
 *
 * Idempotent by construction. `buildUserId` returns the same value for the same
 * identity, and the attribution block is stripped before it is rewritten from a
 * fingerprint over the *first* user message, so a second hop reproduces both
 * values rather than stacking them.
 */
export async function transformBody(
  raw: Uint8Array,
  options: BodyTransformOptions,
): Promise<BodyTransformResult> {
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

  // Only the two endpoints known to carry `system` and `metadata`. Writing
  // either onto an unrecognised shape would be inventing a schema.
  if (options.endpoint === "other") {
    return { body: raw, capabilities: inertCapabilities(model) };
  }

  // Merged rather than replaced: a caller's other metadata keys are its own.
  const metadata = isObject(body.metadata) ? body.metadata : {};
  metadata.user_id = buildUserId(options.identity, metadata.user_id);
  body.metadata = metadata;

  // count_tokens gets the block too, even though the upstream check waves that
  // endpoint through on user-agent alone. The point there is arithmetic rather
  // than admission: the count has to describe the `/v1/messages` request that
  // follows, and that request will carry the block.
  body.system = applyAttribution(
    body.system,
    await buildAttributionText(
      body.messages,
      options.profile.cliVersion,
      options.profile.entrypoint,
    ),
  );

  return {
    body: new TextEncoder().encode(JSON.stringify(body)),
    capabilities: readCapabilities(body),
  };
}
