/**
 * The cloak's own contract.
 *
 * Three properties carry most of the weight here.
 *
 * The first is idempotency. A request can traverse more than one hop of this
 * Worker, so `transform(transform(x)) === transform(x)` is asserted directly
 * rather than inferred from the individual guards -- a second identity block or a
 * second cache breakpoint would grow the prompt and invalidate the cached prefix
 * on every pass.
 *
 * The second is that the beta header describes the body. A beta announced without
 * the field it names is both a fingerprint and a source of upstream 400s, so each
 * capability is tested in both directions: present and absent.
 *
 * The third is that credentials survive. The header builder deletes and rebuilds
 * the whole identity set, and a credential drifting into that set would silently
 * strip upstream authorization, so `x-api-key` and `authorization` are asserted
 * explicitly rather than assumed.
 */
import { describe, expect, it } from "vitest";

import { buildBetaHeader, parseBetaHeader, TOKEN_COUNTING_BETA } from "../src/cloak/beta";
import { transformBody } from "../src/cloak/body";
import { classifyEndpoint } from "../src/cloak/endpoint";
import { buildCloakHeaders, isManagedCloakHeader } from "../src/cloak/headers";
import { buildUserId, deriveIdentity, type ClientIdentity } from "../src/cloak/identity";
import {
  cloakUserAgent,
  DEFAULT_CLOAK_PROFILE,
  readCloakProfile,
} from "../src/cloak/profile";
import { projectClaudeRequest } from "../src/cloak";
import { isStrippedRequestHeader } from "../src/headers";

const TODAY = "2026-08-22";

const IDENTITY: ClientIdentity = {
  deviceId: "a".repeat(64),
  sessionId: "00000000-0000-4000-8000-000000000000",
  accountUuid: "",
};

function encode(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function decode(body: Uint8Array): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
}

function shape(
  body: unknown,
  endpoint: "messages" | "count_tokens" | "other" = "messages",
) {
  return transformBody(encode(body), {
    endpoint,
    identity: IDENTITY,
    contentType: "application/json",
    today: TODAY,
  });
}

const MESSAGES = [{ role: "user", content: "hi" }];

describe("profile", () => {
  it("pins the forensically captured 2.1.239 values", () => {
    // Read out of the native binary. The SDK version is the one the CLI embeds,
    // not the registry's latest -- those diverged at capture time.
    expect(DEFAULT_CLOAK_PROFILE.cliVersion).toBe("2.1.239");
    expect(DEFAULT_CLOAK_PROFILE.sdkVersion).toBe("0.112.1");
    expect(DEFAULT_CLOAK_PROFILE.runtimeVersion).toBe("v26.3.0");
    expect(cloakUserAgent(DEFAULT_CLOAK_PROFILE)).toBe(
      "claude-cli/2.1.239 (external, cli)",
    );
  });

  it("claims the host platform rather than an exotic one", () => {
    // The X-Stainless OS/arch pair derives from the real process in a genuine
    // client, so a Linux egress claiming MacOS/arm64 asserts a machine that is
    // not there.
    expect(DEFAULT_CLOAK_PROFILE.os).toBe("Linux");
    expect(DEFAULT_CLOAK_PROFILE.arch).toBe("x64");
  });

  it("accepts operator overrides and ignores blank ones", () => {
    const overridden = readCloakProfile({
      CLAUDE_CLOAK_CLI_VERSION: "2.1.240",
      CLAUDE_CLOAK_SDK_VERSION: "  ",
    });

    expect(overridden.cliVersion).toBe("2.1.240");
    // A blank variable is how an operator unsets a value; emitting an empty
    // header would be a unique fingerprint of this Worker.
    expect(overridden.sdkVersion).toBe(DEFAULT_CLOAK_PROFILE.sdkVersion);
  });
});

describe("endpoint classification", () => {
  it("separates count_tokens from messages", () => {
    // count_tokens carries its own beta, appended by a different code path in the
    // real client, so conflating the two sends the wrong set both ways.
    expect(classifyEndpoint("/api.anthropic.com/v1/messages")).toBe("messages");
    expect(classifyEndpoint("/api.anthropic.com/v1/messages/count_tokens")).toBe(
      "count_tokens",
    );
    expect(classifyEndpoint("/api.anthropic.com/v1/models")).toBe("other");
  });

  it("tolerates a trailing slash", () => {
    expect(classifyEndpoint("/api.anthropic.com/v1/messages/")).toBe("messages");
  });
});

describe("beta assembly", () => {
  const base = {
    model: "claude-sonnet-4-6",
    hasTools: false,
    hasMcpServers: false,
    hasThinking: false,
    thinkingDisplay: false,
    hasContextManagement: false,
    hasStructuredOutput: false,
    hasEffort: false,
    fastMode: false,
  };

  it("serializes with a bare comma", () => {
    // Array#toString() is the real serializer, so `, ` would be a one-byte tell.
    const header = buildBetaHeader(null, { ...base, hasTools: true }, "messages");
    expect(header).toBe("claude-code-20250219,advanced-tool-use-2025-11-20");
    expect(header).not.toContain(", ");
  });

  it("suppresses the claude-code beta for haiku models", () => {
    // Matches the real builder, which pushes it only when the model name does
    // not contain haiku.
    expect(buildBetaHeader(null, { ...base, model: "claude-haiku-4-5" }, "messages")).toBe(
      null,
    );
  });

  it("announces tools only when tools are present", () => {
    expect(buildBetaHeader(null, base, "messages")).not.toContain(
      "advanced-tool-use",
    );
    expect(
      buildBetaHeader(null, { ...base, hasTools: true }, "messages"),
    ).toContain("advanced-tool-use-2025-11-20");
  });

  it("pairs thinking with its betas and drops redaction when displayed", () => {
    const hidden = buildBetaHeader(null, { ...base, hasThinking: true }, "messages");
    expect(hidden).toContain("interleaved-thinking-2025-05-14");
    expect(hidden).toContain("thinking-token-count-2026-05-13");
    expect(hidden).toContain("redact-thinking-2026-02-12");

    // With a display surface the blocks are meant to return visible, so claiming
    // redaction would contradict the request.
    const shown = buildBetaHeader(
      null,
      { ...base, hasThinking: true, thinkingDisplay: true },
      "messages",
    );
    expect(shown).not.toContain("redact-thinking");
  });

  it("adds fast-mode only for speed:fast", () => {
    expect(buildBetaHeader(null, { ...base, fastMode: true }, "messages")).toContain(
      "fast-mode-2026-02-01",
    );
    expect(buildBetaHeader(null, base, "messages")).not.toContain("fast-mode");
  });

  it("gives count_tokens its own profile", () => {
    const header = buildBetaHeader(null, base, "count_tokens");
    expect(header).toContain(TOKEN_COUNTING_BETA);
    // Appended by the SDK helper, so it lands after the registry-ordered values.
    expect(header?.endsWith(TOKEN_COUNTING_BETA)).toBe(true);
    expect(buildBetaHeader(null, base, "messages")).not.toContain(TOKEN_COUNTING_BETA);
  });

  it("keeps unknown caller betas at the tail", () => {
    // Far more likely to be a feature newer than this file than an error worth
    // discarding.
    const header = buildBetaHeader("some-future-beta-2027-01-01", base, "messages");
    expect(header).toBe("claude-code-20250219,some-future-beta-2027-01-01");
  });

  it("preserves credential-coupled betas it does not model", () => {
    // oauth/extended-cache-ttl belong to the caller's own auth type; dropping
    // them could break a working OAuth request.
    const header = buildBetaHeader("oauth-2025-04-20", base, "messages");
    expect(header).toContain("oauth-2025-04-20");
  });

  it("sorts registered values into declaration order", () => {
    const header = buildBetaHeader(
      null,
      { ...base, hasTools: true, hasThinking: true },
      "messages",
    );
    const order = (header ?? "").split(",");
    expect(order.indexOf("claude-code-20250219")).toBeLessThan(
      order.indexOf("interleaved-thinking-2025-05-14"),
    );
    expect(order.indexOf("interleaved-thinking-2025-05-14")).toBeLessThan(
      order.indexOf("advanced-tool-use-2025-11-20"),
    );
  });

  it("does not duplicate a beta the caller already sent", () => {
    const header = buildBetaHeader("claude-code-20250219", base, "messages");
    expect(header).toBe("claude-code-20250219");
  });

  it("emits nothing rather than an empty header", () => {
    // An empty anthropic-beta is not something a real client sends.
    expect(buildBetaHeader("", { ...base, model: "claude-haiku-4-5" }, "messages")).toBe(
      null,
    );
  });

  it("tolerates a malformed caller header", () => {
    expect(parseBetaHeader(" a , , b ")).toEqual(["a", "b"]);
    expect(parseBetaHeader(null)).toEqual([]);
  });

  it("is idempotent over its own output", () => {
    const capabilities = { ...base, hasTools: true, hasThinking: true };
    const once = buildBetaHeader(null, capabilities, "messages");
    expect(buildBetaHeader(once, capabilities, "messages")).toBe(once);
  });
});

describe("identity derivation", () => {
  it("is stable for a key and distinct across keys", async () => {
    // Random-per-request would present every call as a new device and a new
    // session, which no real client does.
    const a1 = await deriveIdentity("key-a", DEFAULT_CLOAK_PROFILE);
    const a2 = await deriveIdentity("key-a", DEFAULT_CLOAK_PROFILE);
    const b = await deriveIdentity("key-b", DEFAULT_CLOAK_PROFILE);

    expect(a1).toEqual(a2);
    expect(a1.deviceId).not.toBe(b.deviceId);
    expect(a1.sessionId).not.toBe(b.sessionId);
  });

  it("produces a 64-hex device id and a v4-shaped session id", async () => {
    const identity = await deriveIdentity("key-a", DEFAULT_CLOAK_PROFILE);
    expect(identity.deviceId).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.sessionId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it("never derives the device id from the session id", async () => {
    // Distinct salts per field: one shared hash would make each trivially
    // derivable from the other.
    const identity = await deriveIdentity("key-a", DEFAULT_CLOAK_PROFILE);
    expect(identity.deviceId.slice(0, 8)).not.toBe(
      identity.sessionId.slice(0, 8),
    );
  });

  it("keeps an absent key usable", async () => {
    // OAuth-bearer callers legitimately send no x-api-key; failing them would be
    // worse than deriving from the empty string.
    const identity = await deriveIdentity(null, DEFAULT_CLOAK_PROFILE);
    expect(identity.deviceId).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes with the salt", async () => {
    const a = await deriveIdentity("key-a", DEFAULT_CLOAK_PROFILE);
    const b = await deriveIdentity("key-a", {
      ...DEFAULT_CLOAK_PROFILE,
      identitySalt: "other",
    });
    expect(a.deviceId).not.toBe(b.deviceId);
  });

  it("leaves account_uuid empty for api-key auth", async () => {
    // The real client sends "" with no OAuth account attached, so inventing a
    // UUID would be less authentic, not more.
    const identity = await deriveIdentity("key-a", DEFAULT_CLOAK_PROFILE);
    expect(identity.accountUuid).toBe("");
  });
});

describe("metadata.user_id", () => {
  it("is a JSON string with the three identity fields", () => {
    // A nested object would be immediately distinguishable from a real request.
    const userId = buildUserId(IDENTITY, undefined);
    expect(typeof userId).toBe("string");
    expect(JSON.parse(userId)).toEqual({
      device_id: IDENTITY.deviceId,
      account_uuid: "",
      session_id: IDENTITY.sessionId,
    });
  });

  it("overwrites a caller's real identity but keeps its extras", () => {
    // Forwarding a real client's device id would put two machines behind one
    // credential; unrelated application context is legitimate and survives.
    const userId = buildUserId(
      IDENTITY,
      JSON.stringify({ device_id: "b".repeat(64), project: "demo", count: 2 }),
    );
    const parsed = JSON.parse(userId) as Record<string, unknown>;

    expect(parsed.device_id).toBe(IDENTITY.deviceId);
    expect(parsed.project).toBe("demo");
    expect(parsed.count).toBe(2);
  });

  it("drops reserved keys and non-scalar extras", () => {
    const parsed = JSON.parse(
      buildUserId(IDENTITY, JSON.stringify({ tk: "x", nested: { a: 1 } })),
    ) as Record<string, unknown>;

    expect(parsed.tk).toBeUndefined();
    expect(parsed.nested).toBeUndefined();
  });

  it("falls back to the core fields past the 512-char ceiling", () => {
    // The real client discards extras rather than truncating, since truncated
    // JSON would not parse.
    const parsed = JSON.parse(
      buildUserId(IDENTITY, JSON.stringify({ blob: "x".repeat(600) })),
    ) as Record<string, unknown>;

    expect(parsed.blob).toBeUndefined();
    expect(parsed.device_id).toBe(IDENTITY.deviceId);
  });

  it("survives a malformed caller value", () => {
    const parsed = JSON.parse(buildUserId(IDENTITY, "not json")) as Record<
      string,
      unknown
    >;
    expect(parsed.device_id).toBe(IDENTITY.deviceId);
  });

  it("is idempotent", () => {
    const once = buildUserId(IDENTITY, undefined);
    expect(buildUserId(IDENTITY, once)).toBe(once);
  });
});

describe("body shaping", () => {
  it("prepends the identity line and appends the date reminder", () => {
    const body = decode(shape({ model: "claude-sonnet-4-6", messages: MESSAGES }).body);
    const system = body.system as Array<Record<string, unknown>>;

    expect(system[0]?.text).toBe(
      "You are Claude Code, Anthropic's official CLI for Claude.",
    );
    expect(String(system[system.length - 1]?.text)).toContain("# currentDate");
    expect(String(system[system.length - 1]?.text)).toContain(TODAY);
  });

  it("keeps a caller's own system content", () => {
    const body = decode(
      shape({ model: "claude-sonnet-4-6", system: "be terse", messages: MESSAGES }).body,
    );
    const texts = (body.system as Array<Record<string, unknown>>).map((b) => b.text);

    expect(texts).toContain("be terse");
    expect(texts[0]).toBe("You are Claude Code, Anthropic's official CLI for Claude.");
  });

  it("puts the cache breakpoint on the last system block", () => {
    // A breakpoint caches everything up to and including itself, so an earlier
    // block would leave the rest of the prefix uncached.
    const system = decode(
      shape({ model: "claude-sonnet-4-6", messages: MESSAGES }).body,
    ).system as Array<Record<string, unknown>>;

    expect(system[system.length - 1]?.cache_control).toEqual({ type: "ephemeral" });
    expect(system[0]?.cache_control).toBeUndefined();
  });

  it("falls back to tools when there is no system prompt", () => {
    // Stateless callers with a large tool prefix would otherwise re-tokenize it
    // on every request. count_tokens has no system in the common case.
    const result = shape(
      {
        model: "claude-sonnet-4-6",
        tools: [{ name: "read", description: "x" }],
        messages: MESSAGES,
      },
      "count_tokens",
    );
    const body = decode(result.body);
    const system = body.system as Array<Record<string, unknown>>;
    const tools = body.tools as Array<Record<string, unknown>>;

    // The system prompt is still built, so the breakpoint belongs there; the
    // tools path is exercised by the no-system case below.
    expect(system.length).toBeGreaterThan(0);
    expect(tools[0]?.cache_control).toBeUndefined();
  });

  it("adds context_management only alongside thinking", () => {
    // The edit clears thinking blocks, so on a request without any it would
    // describe work that cannot happen.
    const withThinking = decode(
      shape({
        model: "claude-sonnet-4-6",
        thinking: { type: "enabled", budget_tokens: 1024 },
        messages: MESSAGES,
      }).body,
    );
    expect(withThinking.context_management).toEqual({
      edits: [{ type: "clear_thinking_20251015", keep: "all" }],
    });

    const without = decode(
      shape({ model: "claude-sonnet-4-6", messages: MESSAGES }).body,
    );
    expect(without.context_management).toBeUndefined();
  });

  it("never overwrites a caller's own context_management", () => {
    const body = decode(
      shape({
        model: "claude-sonnet-4-6",
        thinking: { type: "enabled" },
        context_management: { edits: [] },
        messages: MESSAGES,
      }).body,
    );
    expect(body.context_management).toEqual({ edits: [] });
  });

  it("reports capabilities from the transformed body", () => {
    // The beta header is derived from this, so it must describe what is actually
    // being sent -- including the context_management this transform just added.
    const result = shape({
      model: "claude-sonnet-4-6",
      thinking: { type: "enabled" },
      messages: MESSAGES,
    });

    expect(result.capabilities.hasThinking).toBe(true);
    expect(result.capabilities.hasContextManagement).toBe(true);
  });

  it("leaves a non-JSON body untouched", () => {
    const raw = new TextEncoder().encode("not json at all");
    const result = transformBody(raw, {
      endpoint: "messages",
      identity: IDENTITY,
      contentType: "application/octet-stream",
      today: TODAY,
    });

    expect(result.body).toBe(raw);
    // Nothing is claimed for a body this module did not shape.
    expect(result.capabilities.hasTools).toBe(false);
  });

  it("leaves unparseable JSON untouched", () => {
    const raw = new TextEncoder().encode("{broken");
    const result = transformBody(raw, {
      endpoint: "messages",
      identity: IDENTITY,
      contentType: "application/json",
      today: TODAY,
    });
    expect(result.body).toBe(raw);
  });

  it("leaves an unrecognised endpoint untouched", () => {
    // Rewriting an unfamiliar shape risks corrupting a request that would
    // otherwise have worked.
    const raw = encode({ model: "claude-sonnet-4-6" });
    expect(shape({ model: "claude-sonnet-4-6" }, "other").body).toEqual(raw);
  });

  it("is idempotent", () => {
    const once = shape({
      model: "claude-sonnet-4-6",
      system: "be terse",
      thinking: { type: "enabled" },
      tools: [{ name: "read" }],
      messages: MESSAGES,
    }).body;

    const twice = transformBody(once, {
      endpoint: "messages",
      identity: IDENTITY,
      contentType: "application/json",
      today: TODAY,
    }).body;

    expect(new TextDecoder().decode(twice)).toBe(new TextDecoder().decode(once));
  });

  it("stays idempotent across a date change", () => {
    // The reminder is matched by marker, not by text, so yesterday's reminder
    // must not attract a second one today.
    const once = shape({ model: "claude-sonnet-4-6", messages: MESSAGES }).body;
    const twice = transformBody(once, {
      endpoint: "messages",
      identity: IDENTITY,
      contentType: "application/json",
      today: "2026-08-23",
    }).body;

    const system = (decode(twice).system as Array<Record<string, unknown>>).filter(
      (block) => String(block.text).includes("# currentDate"),
    );
    expect(system).toHaveLength(1);
  });
});

describe("cloak headers", () => {
  function build(incoming: Record<string, string>, beta: string | null = null): Headers {
    return buildCloakHeaders(new Headers(incoming), DEFAULT_CLOAK_PROFILE, beta);
  }

  it("writes the full Stainless set", () => {
    const headers = build({});

    expect(headers.get("user-agent")).toBe("claude-cli/2.1.239 (external, cli)");
    expect(headers.get("x-stainless-lang")).toBe("js");
    expect(headers.get("x-stainless-runtime")).toBe("node");
    expect(headers.get("x-stainless-runtime-version")).toBe("v26.3.0");
    expect(headers.get("x-stainless-package-version")).toBe("0.112.1");
    expect(headers.get("x-stainless-os")).toBe("Linux");
    expect(headers.get("x-stainless-arch")).toBe("x64");
    expect(headers.get("x-stainless-retry-count")).toBe("0");
    expect(headers.get("anthropic-version")).toBe("2023-06-01");
    expect(headers.get("x-app")).toBe("cli");
    expect(headers.get("accept")).toBe("application/json");
  });

  it("replaces a caller's inconsistent profile rather than merging it", () => {
    // The hard case: a caller that already looks like Claude Code. Merging would
    // pair one release's CLI version with another's SDK version.
    const headers = build({
      "user-agent": "claude-cli/2.1.185 (external, cli)",
      "x-stainless-package-version": "0.94.0",
      "x-stainless-os": "MacOS",
    });

    expect(headers.get("user-agent")).toBe("claude-cli/2.1.239 (external, cli)");
    expect(headers.get("x-stainless-package-version")).toBe("0.112.1");
    expect(headers.get("x-stainless-os")).toBe("Linux");
  });

  it("forwards the caller's credentials untouched", () => {
    // This Worker holds no credential of its own to substitute, so rewriting
    // these would simply break the request.
    const headers = build({ "x-api-key": "caller-key", authorization: "Bearer t" });

    expect(headers.get("x-api-key")).toBe("caller-key");
    expect(headers.get("authorization")).toBe("Bearer t");
    expect(isManagedCloakHeader("x-api-key")).toBe(false);
    expect(isManagedCloakHeader("authorization")).toBe(false);
  });

  it("drops the caller's real Claude Code session identity", () => {
    // Forwarding it would attribute this request to a session that belongs to a
    // different machine.
    const headers = build({
      "x-claude-code-session-id": "11111111-1111-4111-8111-111111111111",
      "x-claude-remote-session-id": "remote",
      "x-client-app": "vscode",
      "anthropic-client-platform": "desktop_app",
    });

    expect(headers.has("x-claude-code-session-id")).toBe(false);
    expect(headers.has("x-claude-remote-session-id")).toBe(false);
    expect(headers.has("x-client-app")).toBe(false);
    expect(headers.has("anthropic-client-platform")).toBe(false);
  });

  it("omits an empty beta header but writes a present one", () => {
    expect(build({}, null).has("anthropic-beta")).toBe(false);
    expect(build({}, "claude-code-20250219").get("anthropic-beta")).toBe(
      "claude-code-20250219",
    );
  });

  it("keeps unrelated caller headers", () => {
    expect(build({ "content-type": "application/json" }).get("content-type")).toBe(
      "application/json",
    );
  });

  it("is idempotent", () => {
    const once = build({ "content-type": "application/json" }, "claude-code-20250219");
    const twice = buildCloakHeaders(once, DEFAULT_CLOAK_PROFILE, "claude-code-20250219");

    expect([...twice].sort()).toEqual([...once].sort());
  });
});

describe("Cloudflare header leakage", () => {
  /**
   * `cf-pseudo-ipv4` reached a real upstream through this Worker: it was added to
   * the platform after the named strip list was written. The prefix rule is what
   * makes the next such header a non-event.
   */
  it("strips every cf- header, including ones added after this test", () => {
    for (const name of [
      "cf-connecting-ip",
      "cf-pseudo-ipv4",
      "cf-ray",
      "cf-worker",
      "cf-ipcountry",
      "cf-some-header-cloudflare-adds-later",
    ]) {
      expect(isStrippedRequestHeader(name)).toBe(true);
      expect(isStrippedRequestHeader(name.toUpperCase())).toBe(true);
    }
  });

  it("still strips the non-cf source-revealing headers", () => {
    for (const name of ["x-forwarded-for", "x-real-ip", "forwarded", "cdn-loop"]) {
      expect(isStrippedRequestHeader(name)).toBe(true);
    }
  });

  it("does not strip anything the upstream needs", () => {
    for (const name of ["x-api-key", "authorization", "content-type", "anthropic-beta"]) {
      expect(isStrippedRequestHeader(name)).toBe(false);
    }
  });
});

describe("projectClaudeRequest", () => {
  function request(body: unknown, headers: Record<string, string> = {}): Request {
    return new Request("https://w.example/api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "k", ...headers },
      body: JSON.stringify(body),
    });
  }

  const deps = { today: () => TODAY };

  it("derives the beta header from the body, not from the caller", async () => {
    // The caller claims tool use on a request with no tools; the header must
    // describe the body that is actually sent.
    const projected = await projectClaudeRequest(
      request({ model: "claude-sonnet-4-6", messages: MESSAGES }, {
        "anthropic-beta": "advanced-tool-use-2025-11-20",
      }),
      encode({ model: "claude-sonnet-4-6", messages: MESSAGES }),
      {},
      deps,
    );

    expect(projected.headers.get("anthropic-beta")).toBe("claude-code-20250219");
  });

  it("announces tools when the body has them", async () => {
    const body = {
      model: "claude-sonnet-4-6",
      tools: [{ name: "read" }],
      messages: MESSAGES,
    };
    const projected = await projectClaudeRequest(
      request(body),
      encode(body),
      {},
      deps,
    );

    expect(projected.headers.get("anthropic-beta")).toContain(
      "advanced-tool-use-2025-11-20",
    );
  });

  it("uses the count_tokens profile on that endpoint", async () => {
    const body = { model: "claude-sonnet-4-6", messages: MESSAGES };
    const projected = await projectClaudeRequest(
      new Request("https://w.example/api.anthropic.com/v1/messages/count_tokens", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": "k" },
        body: JSON.stringify(body),
      }),
      encode(body),
      {},
      deps,
    );

    expect(projected.headers.get("anthropic-beta")).toContain(TOKEN_COUNTING_BETA);
  });

  it("writes a stable identity into the body", async () => {
    const body = { model: "claude-sonnet-4-6", messages: MESSAGES };
    const first = await projectClaudeRequest(request(body), encode(body), {}, deps);
    const second = await projectClaudeRequest(request(body), encode(body), {}, deps);

    expect(new TextDecoder().decode(first.body)).toBe(
      new TextDecoder().decode(second.body),
    );
    const metadata = decode(first.body).metadata as Record<string, unknown>;
    expect(JSON.parse(String(metadata.user_id)).device_id).toMatch(/^[0-9a-f]{64}$/);
  });

  it("gives different callers different identities", async () => {
    const body = { model: "claude-sonnet-4-6", messages: MESSAGES };
    const a = await projectClaudeRequest(
      request(body, { "x-api-key": "key-a" }),
      encode(body),
      {},
      deps,
    );
    const b = await projectClaudeRequest(
      request(body, { "x-api-key": "key-b" }),
      encode(body),
      {},
      deps,
    );

    const deviceOf = (payload: Uint8Array) =>
      JSON.parse(
        String((decode(payload).metadata as Record<string, unknown>).user_id),
      ).device_id;

    expect(deviceOf(a.body)).not.toBe(deviceOf(b.body));
  });

  it("is idempotent end to end", async () => {
    // The property that makes it safe for a request to cross more than one hop.
    const body = {
      model: "claude-sonnet-4-6",
      thinking: { type: "enabled" },
      messages: MESSAGES,
    };
    const once = await projectClaudeRequest(request(body), encode(body), {}, deps);

    const replay = new Request("https://w.example/api.anthropic.com/v1/messages", {
      method: "POST",
      headers: once.headers,
      body: new TextDecoder().decode(once.body),
    });
    const twice = await projectClaudeRequest(replay, once.body, {}, deps);

    expect(new TextDecoder().decode(twice.body)).toBe(
      new TextDecoder().decode(once.body),
    );
    expect(twice.headers.get("anthropic-beta")).toBe(
      once.headers.get("anthropic-beta"),
    );
    expect(twice.headers.get("user-agent")).toBe(once.headers.get("user-agent"));
  });
});
