import type { IdentityConfig } from "./config";

export const IDENTITY_HEADERS = [
  "user-agent",
  "originator",
  "session-id",
  "session_id",
  "thread-id",
  "thread_id",
  "x-client-request-id",
  "x-codex-window-id",
  "x-codex-installation-id",
  "x-codex-beta-features",
  "x-codex-turn-metadata",
  "accept-encoding",
] as const;

export const HOP_BY_HOP_HEADERS = [
  "host",
  "content-length",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "proxy-authorization",
  "proxy-connection",
] as const;

export interface IdentityDependencies {
  randomUUID: () => string;
  now: () => number;
}

const runtimeDependencies: IdentityDependencies = {
  randomUUID: () => crypto.randomUUID(),
  now: () => Date.now(),
};

function isCodex(value: string): boolean {
  return value.startsWith("codex-") || value.startsWith("codex_");
}

function getHeader(headers: Headers, name: string): string {
  return headers.get(name) ?? "";
}

export class ResolvedIdentity {
  constructor(
    readonly userAgent: string,
    readonly originator: string,
    readonly acceptEncoding: string,
    readonly sessionId: string,
    readonly threadId: string,
    readonly requestId: string,
    readonly windowId: string,
    readonly installationId: string,
    readonly betaFeatures: string,
    readonly turnId: string,
    readonly turnStartedAtUnixMs: number,
    readonly clientTurnMetadata?: string,
  ) {}

  ensureBodyMetadata(contentType: string | null | undefined, body: Uint8Array): Uint8Array {
    if (!contentType?.toLowerCase().includes("application/json")) {
      return body;
    }

    let value: unknown;
    try {
      value = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return body;
    }

    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return body;
    }

    const object = value as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(object, "client_metadata")) {
      return body;
    }

    object.client_metadata = this.clientMetadata();
    return new TextEncoder().encode(JSON.stringify(object));
  }

  turnMetadataJson(): string {
    if (this.clientTurnMetadata) {
      return this.clientTurnMetadata;
    }

    return JSON.stringify({
      installation_id: this.installationId,
      session_id: this.sessionId,
      thread_id: this.threadId,
      turn_id: this.turnId,
      window_id: this.windowId,
      request_kind: "turn",
      thread_source: "user",
      sandbox: "none",
      turn_started_at_unix_ms: this.turnStartedAtUnixMs,
    });
  }

  private clientMetadata(): Record<string, unknown> {
    return {
      "x-codex-installation-id": this.installationId,
      "x-codex-turn-metadata": this.turnMetadataJson(),
      "x-codex-window-id": this.windowId,
      thread_id: this.threadId,
      turn_id: this.turnId,
      session_id: this.sessionId,
    };
  }
}

export function resolveIdentity(
  incoming: Headers,
  config: IdentityConfig,
  dependencies: IdentityDependencies = runtimeDependencies,
): ResolvedIdentity {
  const clientUa = getHeader(incoming, "user-agent");
  const clientOriginator = getHeader(incoming, "originator");
  const clientSession = getHeader(incoming, "session-id") || getHeader(incoming, "session_id");
  const clientThread = getHeader(incoming, "thread-id") || getHeader(incoming, "thread_id");
  const clientRequestId = getHeader(incoming, "x-client-request-id");
  const clientWindow = getHeader(incoming, "x-codex-window-id");
  const clientInstallation = getHeader(incoming, "x-codex-installation-id");
  const clientBeta = getHeader(incoming, "x-codex-beta-features");
  const clientTurnMetadata = getHeader(incoming, "x-codex-turn-metadata");

  const userAgent = isCodex(clientUa) ? clientUa : config.userAgent;
  const originator = isCodex(clientOriginator) ? clientOriginator : config.originator;
  const sessionId = clientSession || dependencies.randomUUID();
  const threadId = clientThread || sessionId;
  const installationId = clientInstallation || config.installationId;
  // Upstream formats the window id from the thread id, not the session id:
  // `Session::current_window_id()` builds `{thread_id}:{window_number}`
  // (codex-rs/core/src/session/mod.rs:3741) and codex-rs/core/tests/responses_headers.rs:109
  // asserts `{thread_id}:0` for a fresh window.
  const windowId = clientWindow || `${threadId}:0`;
  // Upstream sends the thread id as x-client-request-id
  // (codex-rs/codex-api/src/endpoint/responses.rs:89).
  const requestId = clientRequestId || threadId;
  const betaFeatures = clientBeta || config.betaFeatures;

  return new ResolvedIdentity(
    userAgent,
    originator,
    config.acceptEncoding,
    sessionId,
    threadId,
    requestId,
    windowId,
    installationId,
    betaFeatures,
    dependencies.randomUUID(),
    dependencies.now(),
    clientTurnMetadata || undefined,
  );
}

export function projectIdentity(identity: ResolvedIdentity, incoming: Headers): Headers {
  const output = new Headers();
  for (const [name, value] of incoming) {
    if (
      HOP_BY_HOP_HEADERS.includes(name as (typeof HOP_BY_HOP_HEADERS)[number]) ||
      IDENTITY_HEADERS.includes(name as (typeof IDENTITY_HEADERS)[number])
    ) {
      continue;
    }
    output.set(name, value);
  }

  output.set("user-agent", identity.userAgent);
  output.set("originator", identity.originator);
  output.set("accept-encoding", identity.acceptEncoding);
  output.set("session-id", identity.sessionId);
  output.set("thread-id", identity.threadId);
  output.set("x-client-request-id", identity.requestId);
  output.set("x-codex-window-id", identity.windowId);
  output.set("x-codex-installation-id", identity.installationId);
  output.set("x-codex-beta-features", identity.betaFeatures);
  output.set("x-codex-turn-metadata", identity.turnMetadataJson());

  return output;
}
