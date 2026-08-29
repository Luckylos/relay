import { describe, expect, it } from "vitest";
import {
  DEFAULT_BETA_FEATURES,
  DEFAULT_ORIGINATOR,
  DEFAULT_UA_VERSION,
  buildDefaultUserAgent,
  readIdentityConfig,
} from "../src/config";
import {
  HOP_BY_HOP_HEADERS,
  IDENTITY_HEADERS,
  ResolvedIdentity,
  projectIdentity,
  resolveIdentity,
} from "../src/identity";

const FIXED_INSTALLATION = "11111111-1111-1111-1111-111111111111";
const CONFIG_ENV = {
  CODEX_PROXY_INSTALLATION_ID: FIXED_INSTALLATION,
};

function config() {
  return readIdentityConfig(CONFIG_ENV, () => "unused");
}

function deterministicIdentity(incoming: Headers = new Headers()) {
  const ids = [
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  ];
  return resolveIdentity(incoming, config(), {
    randomUUID: () => ids.shift() ?? "unexpected-id",
    now: () => 1700000000000,
  });
}

describe("identity configuration", () => {
  it("builds the captured Codex user-agent shape", () => {
    expect(buildDefaultUserAgent("codex-tui", "0.149.0", "Debian 12.0.0; x86_64", "unknown")).toBe(
      "codex-tui/0.149.0 (Debian 12.0.0; x86_64) unknown (codex-tui; 0.149.0)",
    );
  });

  it("uses the frozen defaults", () => {
    const value = readIdentityConfig({ CODEX_PROXY_INSTALLATION_ID: FIXED_INSTALLATION }, () => "id");
    expect(value.userAgent).toContain(`${DEFAULT_ORIGINATOR}/${DEFAULT_UA_VERSION}`);
    expect(value.originator).toBe(DEFAULT_ORIGINATOR);
    expect(value.betaFeatures).toBe(DEFAULT_BETA_FEATURES);
    expect(value.installationId).toBe(FIXED_INSTALLATION);
  });
});

describe("projectIdentity", () => {
  it("synthesizes one coherent identity for a non-Codex client", () => {
    const identity = deterministicIdentity(new Headers({ "user-agent": "curl/8.0" }));
    const headers = projectIdentity(identity, new Headers({ "user-agent": "curl/8.0" }));
    const session = headers.get("session-id");

    expect(headers.get("user-agent")).toBe(config().userAgent);
    expect(headers.get("originator")).toBe(DEFAULT_ORIGINATOR);
    expect(session).toBe("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    expect(headers.get("thread-id")).toBe(session);
    expect(headers.get("x-client-request-id")).toBe(session);
    expect(headers.get("x-codex-window-id")).toBe(`${session}:0`);
    // A real main `/responses` turn carries neither of these as HTTP headers.
    expect(headers.has("accept-encoding")).toBe(false);
    expect(headers.has("x-codex-installation-id")).toBe(false);

    const turnMetadata = JSON.parse(headers.get("x-codex-turn-metadata") ?? "{}");
    expect(turnMetadata).toMatchObject({
      installation_id: FIXED_INSTALLATION,
      session_id: session,
      thread_id: session,
      turn_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      window_id: `${session}:0`,
      request_kind: "turn",
      thread_source: "user",
      sandbox: "none",
      turn_started_at_unix_ms: 1700000000000,
    });
  });

  it("preserves genuine Codex UA, originator, and session values", () => {
    const incoming = new Headers({
      "user-agent": "codex-tui/0.145.0 (Ubuntu 24.04; x86_64) WezTerm (codex-tui; 0.145.0)",
      originator: "codex-tui",
      "session-id": "client-session",
      "thread-id": "client-thread",
      "x-client-request-id": "client-request",
      "x-codex-window-id": "client-window",
      "x-codex-installation-id": "client-installation",
      "x-codex-beta-features": "client-beta",
      "x-codex-turn-metadata": '{"client":true}',
    });

    const identity = deterministicIdentity(incoming);
    const headers = projectIdentity(identity, incoming);

    expect(headers.get("user-agent")).toBe(incoming.get("user-agent"));
    expect(headers.get("originator")).toBe("codex-tui");
    expect(headers.get("session-id")).toBe("client-session");
    expect(headers.get("thread-id")).toBe("client-thread");
    expect(headers.get("x-client-request-id")).toBe("client-request");
    expect(headers.get("x-codex-window-id")).toBe("client-window");
    expect(headers.has("x-codex-installation-id")).toBe(false);
    expect(headers.get("x-codex-beta-features")).toBe("client-beta");
    expect(headers.get("x-codex-turn-metadata")).toBe('{"client":true}');
  });

  it("derives window id and client request id from the thread id, not the session id", () => {
    const incoming = new Headers({
      "session-id": "client-session",
      "thread-id": "client-thread",
    });

    const headers = projectIdentity(deterministicIdentity(incoming), incoming);

    expect(headers.get("session-id")).toBe("client-session");
    expect(headers.get("thread-id")).toBe("client-thread");
    expect(headers.get("x-client-request-id")).toBe("client-thread");
    expect(headers.get("x-codex-window-id")).toBe("client-thread:0");

    const turnMetadata = JSON.parse(headers.get("x-codex-turn-metadata") ?? "{}");
    expect(turnMetadata.window_id).toBe("client-thread:0");
    expect(turnMetadata.session_id).toBe("client-session");
    expect(turnMetadata.thread_id).toBe("client-thread");
  });

  it("prefers hyphenated aliases and emits exactly one canonical identity header", () => {
    const incoming = new Headers();
    incoming.set("session_id", "underscore-session");
    incoming.set("session-id", "hyphen-session");
    incoming.set("thread_id", "underscore-thread");
    incoming.set("thread-id", "hyphen-thread");

    const headers = projectIdentity(deterministicIdentity(incoming), incoming);

    expect(headers.get("session-id")).toBe("hyphen-session");
    expect(headers.get("thread-id")).toBe("hyphen-thread");
    expect(headers.has("session_id")).toBe(false);
    expect(headers.has("thread_id")).toBe(false);
    const projectedIdentityNames = Array.from(headers.keys()).filter((name) =>
      IDENTITY_HEADERS.includes(name as (typeof IDENTITY_HEADERS)[number]),
    );
    expect(projectedIdentityNames).toHaveLength(8);
    expect(new Set(projectedIdentityNames).size).toBe(8);
  });

  it("passes through ordinary headers and strips request hop-by-hop headers", () => {
    const incoming = new Headers({
      authorization: "Bearer sk-test",
      "content-type": "application/json",
      host: "relay.example",
      connection: "keep-alive",
      "proxy-authorization": "Basic secret",
      "transfer-encoding": "chunked",
    });

    const headers = projectIdentity(deterministicIdentity(incoming), incoming);

    expect(headers.get("authorization")).toBe("Bearer sk-test");
    expect(headers.get("content-type")).toBe("application/json");
    for (const name of HOP_BY_HOP_HEADERS) {
      expect(headers.has(name)).toBe(false);
    }
  });
});

describe("identity body projection", () => {
  it("injects metadata into a JSON object and keeps it coherent with headers", () => {
    const identity = deterministicIdentity();
    const body = new TextEncoder().encode('{"model":"gpt-5.6-terra","stream":true}');
    const output = identity.ensureBodyMetadata("application/json", body);
    const value = JSON.parse(new TextDecoder().decode(output));
    const headers = projectIdentity(identity, new Headers());
    const turnMetadata = JSON.parse(headers.get("x-codex-turn-metadata") ?? "{}");

    expect(value).toMatchObject({ model: "gpt-5.6-terra", stream: true });
    expect(value.client_metadata).toMatchObject({
      "x-codex-installation-id": FIXED_INSTALLATION,
      "x-codex-window-id": headers.get("x-codex-window-id"),
      thread_id: headers.get("thread-id"),
      session_id: headers.get("session-id"),
      turn_id: turnMetadata.turn_id,
      "x-codex-turn-metadata": headers.get("x-codex-turn-metadata"),
    });
  });

  it("keeps the installation id in the body even though no header is sent", () => {
    const identity = deterministicIdentity();
    const headers = projectIdentity(identity, new Headers());
    const body = new TextEncoder().encode('{"model":"m"}');
    const value = JSON.parse(
      new TextDecoder().decode(identity.ensureBodyMetadata("application/json", body)),
    );

    expect(headers.has("x-codex-installation-id")).toBe(false);
    expect(value.client_metadata["x-codex-installation-id"]).toBe(FIXED_INSTALLATION);
  });

  it("escapes non-ASCII turn metadata so it stays a valid header value", () => {
    // Upstream serializes this blob with to_ascii_json_string
    // (codex-rs/utils/string/src/json.rs:46) precisely so it survives an
    // ASCII-only transport. Built directly rather than through a non-ASCII
    // request header, which is a separate concern.
    const identity = new ResolvedIdentity(
      "codex-tui/0.149.0 (Debian 12.0.0; x86_64) unknown (codex-tui; 0.149.0)",
      "codex-tui",
      "session",
      "t\u00e9st-\u4e2d\u6587",
      "request",
      "window",
      FIXED_INSTALLATION,
      "beta",
      "turn",
      1700000000000,
    );

    const raw = identity.turnMetadataJson();

    expect(raw).toMatch(/^[\u0000-\u007f]*$/);
    expect(raw).toContain("\\u00e9");
    expect(raw).not.toContain("\u00e9");
    expect(JSON.parse(raw).thread_id).toBe("t\u00e9st-\u4e2d\u6587");
  });

  it("leaves an existing client_metadata body byte-for-byte unchanged", () => {
    const identity = deterministicIdentity();
    const original = new TextEncoder().encode(
      '{ "model": "m", "client_metadata": {"x-codex-installation-id":"real"} }',
    );

    expect(identity.ensureBodyMetadata("application/json", original)).toEqual(original);
  });

  it.each([
    ["text/plain", "not json"],
    ["application/json", "{bad"],
    ["application/json", "[1,2,3]"],
    ["application/json", "42"],
    [undefined, '{"model":"m"}'],
  ])("leaves non-object or non-JSON body %j unchanged", (contentType, raw) => {
    const identity = deterministicIdentity();
    const original = new TextEncoder().encode(raw);
    expect(identity.ensureBodyMetadata(contentType, original)).toEqual(original);
  });
});
