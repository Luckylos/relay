export interface IdentityEnv {
  CODEX_PROXY_UA_VERSION?: string;
  CODEX_PROXY_ORIGINATOR?: string;
  CODEX_PROXY_UA_OS?: string;
  CODEX_PROXY_UA_TERMINAL?: string;
  CODEX_PROXY_USER_AGENT?: string;
  CODEX_PROXY_BETA_FEATURES?: string;
  CODEX_PROXY_INSTALLATION_ID?: string;
  CODEX_PROXY_ACCEPT_ENCODING?: string;
}

export interface IdentityConfig {
  userAgent: string;
  originator: string;
  betaFeatures: string;
  installationId: string;
  acceptEncoding: string;
}

export const DEFAULT_UA_VERSION = "0.145.0";
export const DEFAULT_ORIGINATOR = "codex-tui";
export const DEFAULT_UA_OS = "Debian 12.0.0; x86_64";
export const DEFAULT_UA_TERMINAL = "unknown";
export const DEFAULT_BETA_FEATURES = "remote_compaction_v2";
export const DEFAULT_ACCEPT_ENCODING = "gzip, deflate";

function envOr(value: string | undefined, fallback: string): string {
  return value?.length ? value : fallback;
}

export function buildDefaultUserAgent(
  originator: string,
  version: string,
  os: string,
  terminal: string,
): string {
  return `${originator}/${version} (${os}) ${terminal} (${originator}; ${version})`;
}

export function readIdentityConfig(
  env: IdentityEnv,
  randomUUID: () => string = () => crypto.randomUUID(),
): IdentityConfig {
  const version = envOr(env.CODEX_PROXY_UA_VERSION, DEFAULT_UA_VERSION);
  const originator = envOr(env.CODEX_PROXY_ORIGINATOR, DEFAULT_ORIGINATOR);
  const os = envOr(env.CODEX_PROXY_UA_OS, DEFAULT_UA_OS);
  const terminal = envOr(env.CODEX_PROXY_UA_TERMINAL, DEFAULT_UA_TERMINAL);

  return {
    userAgent: envOr(
      env.CODEX_PROXY_USER_AGENT,
      buildDefaultUserAgent(originator, version, os, terminal),
    ),
    originator,
    betaFeatures: envOr(env.CODEX_PROXY_BETA_FEATURES, DEFAULT_BETA_FEATURES),
    installationId: envOr(env.CODEX_PROXY_INSTALLATION_ID, randomUUID()),
    acceptEncoding: envOr(env.CODEX_PROXY_ACCEPT_ENCODING, DEFAULT_ACCEPT_ENCODING),
  };
}
