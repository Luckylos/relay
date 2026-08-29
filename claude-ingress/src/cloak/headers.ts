/**
 * Client-identity headers.
 *
 * The rule here is delete-then-rebuild, never merge. A caller that already sends
 * Claude Code headers is the *hard* case, not the easy one: its values describe
 * its own machine, its own CLI build and its own session, and forwarding any
 * subset of them alongside this Worker's values produces a client that is
 * internally inconsistent -- an SDK version from one release with a CLI version
 * from another, or two different session identities behind one credential.
 * Rebuilding the whole set from one pinned profile is what keeps the presented
 * client coherent, and it is also what makes the transform idempotent: the second
 * pass deletes exactly what the first pass wrote and writes it again.
 *
 * Credentials are deliberately *not* in the managed set. `x-api-key` and
 * `authorization` are the caller's own upstream authorization and are forwarded
 * untouched; rewriting them would break the request, and this Worker holds no
 * credential of its own to substitute.
 */
import type { ClaudeEndpoint } from "./beta";
import type { CloakProfile } from "./profile";
import { cloakUserAgent } from "./profile";

/**
 * Headers this module owns and rebuilds on every pass.
 *
 * Each entry is here for one of three reasons: it is part of the client profile
 * (`user-agent`, the `x-stainless-*` family, `anthropic-version`), it identifies
 * the caller's real Claude Code installation (`x-claude-code-*`,
 * `x-claude-remote-*`, `x-client-app`), or it is injected by a fronting service
 * and would describe an ingress this request did not come through
 * (`anthropic-client-platform`).
 *
 * `x-stainless-retry-count` is rebuilt rather than forwarded because a
 * caller-supplied retry count describes retries against a different endpoint.
 *
 * `x-stainless-timeout` is rebuilt, not dropped. An earlier revision dropped it
 * on the theory that the emitting condition was unobservable here; reading the
 * binary showed the opposite. The SDK emits it whenever the *call site* passed a
 * timeout, and `messages.create` always passes one
 * (`timeout: s ?? 600000`), while `countTokens` passes none at all. Both
 * conditions are therefore fully determined by the endpoint, and a real
 * `/v1/messages` request always carries `X-Stainless-Timeout: 600`.
 *
 * `x-stainless-helper` and `x-stainless-helper-method` stay dropped: those are
 * attached by the SDK's streaming/tool-runner helpers based on which wrapper the
 * caller invoked, which genuinely is not observable from the wire.
 */
const MANAGED_HEADERS: readonly string[] = [
  "accept",
  "anthropic-beta",
  "anthropic-client-platform",
  "anthropic-dangerous-direct-browser-access",
  "anthropic-version",
  "user-agent",
  "x-app",
  "x-claude-code-agent-id",
  "x-claude-code-parent-agent-id",
  "x-claude-code-session-id",
  "x-claude-remote-container-id",
  "x-claude-remote-session-id",
  "x-client-app",
  "x-stainless-arch",
  "x-stainless-helper",
  "x-stainless-helper-method",
  "x-stainless-lang",
  "x-stainless-os",
  "x-stainless-package-version",
  "x-stainless-retry-count",
  "x-stainless-runtime",
  "x-stainless-runtime-version",
  "x-stainless-timeout",
] as const;

const MANAGED: ReadonlySet<string> = new Set(MANAGED_HEADERS);

/**
 * True when a header is rebuilt from the profile rather than forwarded.
 *
 * Exported for the tests that assert the managed set and the forwarded set do
 * not overlap -- a credential drifting into `MANAGED_HEADERS` would silently
 * strip upstream authorization.
 */
export function isManagedCloakHeader(name: string): boolean {
  return MANAGED.has(name.toLowerCase());
}

/**
 * Rebuild the identity headers over the caller's remaining ones.
 *
 * `betaHeader` is `null` when the request justifies no betas, in which case the
 * header is omitted entirely rather than sent empty -- an empty `anthropic-beta`
 * is not something a real client emits.
 *
 * Header *names* are written in the casing the SDK uses on the wire. It is
 * likely cosmetic, since the relay reaches upstream over HTTP/2 where names are
 * lowercased, but the relay's canonical block preserves what it is given and
 * costing nothing to be accurate is worth more than assuming the normalization.
 */
export function buildCloakHeaders(
  incoming: Headers,
  profile: CloakProfile,
  betaHeader: string | null,
  endpoint: ClaudeEndpoint = "messages",
): Headers {
  const output = new Headers();
  for (const [name, value] of incoming) {
    if (!isManagedCloakHeader(name)) {
      output.set(name, value);
    }
  }

  output.set("Accept", "application/json");
  output.set("User-Agent", cloakUserAgent(profile));
  output.set("anthropic-version", profile.anthropicVersion);
  output.set("x-app", "cli");
  output.set("X-Stainless-Lang", "js");
  output.set("X-Stainless-Package-Version", profile.sdkVersion);
  output.set("X-Stainless-OS", profile.os);
  output.set("X-Stainless-Arch", profile.arch);
  output.set("X-Stainless-Runtime", "node");
  output.set("X-Stainless-Runtime-Version", profile.runtimeVersion);
  // Always "0": this Worker forwards once and does not retry, so any other value
  // would claim a retry that never happened.
  output.set("X-Stainless-Retry-Count", "0");

  // The CLI builds its client with `dangerouslyAllowBrowser: true`, which is what
  // makes the SDK emit this unconditionally. It looks like a header a proxy would
  // never bother to send, which is exactly why omitting it is a tell.
  output.set("anthropic-dangerous-direct-browser-access", "true");

  // Present on /v1/messages, absent on count_tokens -- see the module note. The
  // asymmetry is the authentic shape; sending it on both would be a new tell.
  if (endpoint !== "count_tokens") {
    output.set("X-Stainless-Timeout", profile.timeoutSeconds);
  }

  if (betaHeader !== null) {
    output.set("anthropic-beta", betaHeader);
  }

  return output;
}
