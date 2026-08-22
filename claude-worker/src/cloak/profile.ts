/**
 * The Claude Code client profile this Worker presents upstream.
 *
 * Every value here was read out of the Bun-compiled `claude` native binary
 * (`@anthropic-ai/claude-code-linux-x64`), not from documentation and not from
 * another proxy's configuration. That distinction matters: the top-level
 * `@anthropic-ai/claude-code` npm package is only a platform installer, and the
 * registry's `@anthropic-ai/sdk@latest` is *not* the SDK the CLI ships (0.112.1
 * embedded versus 0.120.0 published at the time of capture). Taking either as
 * ground truth produces a profile that no real client sends.
 *
 * The profile is pinned as one unit rather than field by field. CLI version, SDK
 * version and the beta set drift together between releases -- 2.1.220 -> 2.1.231
 * moved the SDK from 0.94.0 to 0.112.1 and added three betas -- so bumping the
 * user-agent alone yields a combination that never shipped, which is a worse
 * fingerprint than an older but self-consistent one.
 */

/**
 * Overrides, so a version bump is a variable change rather than a redeploy.
 *
 * Deliberately *not* caller-controlled: these are operator variables read from
 * the environment. Letting a request choose its own version fields would let any
 * caller invent an inconsistent client, which is the exact failure this module
 * exists to prevent.
 */
export interface CloakProfileEnv {
  CLAUDE_CLOAK_CLI_VERSION?: string;
  CLAUDE_CLOAK_SDK_VERSION?: string;
  CLAUDE_CLOAK_RUNTIME_VERSION?: string;
  CLAUDE_CLOAK_OS?: string;
  CLAUDE_CLOAK_ARCH?: string;
  /** Domain separator for derived identity. See identity.ts. */
  CLAUDE_CLOAK_IDENTITY_SALT?: string;
}

export interface CloakProfile {
  readonly cliVersion: string;
  readonly sdkVersion: string;
  readonly runtimeVersion: string;
  readonly os: string;
  readonly arch: string;
  readonly entrypoint: string;
  readonly anthropicVersion: string;
  readonly identitySalt: string;
}

/**
 * Captured from CLI 2.1.239 (build 2026-08-21T04:40:30Z, git
 * 9bf8e9521fe06414183309865310e27c9b8db3dd).
 *
 * `os`/`arch` claim Linux/x64 because that is what the egress host actually is.
 * The `X-Stainless-*` pair is derived from `process.platform`/`process.arch` in a
 * real client, so a request leaving a Linux VPS while claiming `MacOS`/`arm64`
 * asserts a machine that is not there. Consistency is the goal, not exoticism.
 *
 * `anthropicVersion` is the SDK's hardcoded API version, unrelated to the CLI
 * release, which is why it is not bumped alongside the others.
 */
export const DEFAULT_CLOAK_PROFILE: CloakProfile = {
  cliVersion: "2.1.239",
  sdkVersion: "0.112.1",
  runtimeVersion: "v26.3.0",
  os: "Linux",
  arch: "x64",
  entrypoint: "cli",
  anthropicVersion: "2023-06-01",
  identitySalt: "claude-worker-relay/v1",
};

/**
 * Non-empty override or the pinned default.
 *
 * An empty string is treated as absent rather than as an instruction to send an
 * empty header: a blank variable is how an operator unsets a value, and emitting
 * `X-Stainless-Arch: ` would be a unique fingerprint of this Worker.
 */
function override(raw: string | undefined, fallback: string): string {
  const trimmed = raw?.trim();
  return trimmed ? trimmed : fallback;
}

export function readCloakProfile(env: CloakProfileEnv): CloakProfile {
  return {
    cliVersion: override(env.CLAUDE_CLOAK_CLI_VERSION, DEFAULT_CLOAK_PROFILE.cliVersion),
    sdkVersion: override(env.CLAUDE_CLOAK_SDK_VERSION, DEFAULT_CLOAK_PROFILE.sdkVersion),
    runtimeVersion: override(
      env.CLAUDE_CLOAK_RUNTIME_VERSION,
      DEFAULT_CLOAK_PROFILE.runtimeVersion,
    ),
    os: override(env.CLAUDE_CLOAK_OS, DEFAULT_CLOAK_PROFILE.os),
    arch: override(env.CLAUDE_CLOAK_ARCH, DEFAULT_CLOAK_PROFILE.arch),
    entrypoint: DEFAULT_CLOAK_PROFILE.entrypoint,
    anthropicVersion: DEFAULT_CLOAK_PROFILE.anthropicVersion,
    identitySalt: override(
      env.CLAUDE_CLOAK_IDENTITY_SALT,
      DEFAULT_CLOAK_PROFILE.identitySalt,
    ),
  };
}

/**
 * `claude-cli/<version> (external, <entrypoint>)`.
 *
 * The real builder can append `, agent-sdk/...`, `, client-app/...` and
 * `, workload/...` when the corresponding environment variables are set in the
 * client. None are appended here: those suffixes advertise an SDK embedding this
 * Worker is not, and the bare CLI form is the common case.
 */
export function cloakUserAgent(profile: CloakProfile): string {
  return `claude-cli/${profile.cliVersion} (external, ${profile.entrypoint})`;
}

/** The CLI's default system-prompt identity line, verbatim. */
export const CLAUDE_CODE_SYSTEM_IDENTITY =
  "You are Claude Code, Anthropic's official CLI for Claude.";
