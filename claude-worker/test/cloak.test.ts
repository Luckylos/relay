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

import {
  applyAttribution,
  buildAttributionText,
  computeFingerprint,
  extractFirstUserText,
  isAttributionText,
} from "../src/cloak/attribution";
import {
  buildBetaHeader,
  type ClaudeEndpoint,
  parseBetaHeader,
  TOKEN_COUNTING_BETA,
} from "../src/cloak/beta";
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
    profile: DEFAULT_CLOAK_PROFILE,
    contentType: "application/json",
  });
}

const MESSAGES = [{ role: "user", content: "hi" }];

/**
 * The attribution block for `MESSAGES` under the pinned profile.
 *
 * "hi" is shorter than every sampled offset, so all three fall back to '0' and
 * the fingerprint is the same one an empty opener produces.
 */
const MESSAGES_ATTRIBUTION =
  "x-anthropic-billing-header: cc_version=2.1.239.5e2; cc_entrypoint=cli;";

/** The block, as it appears once written into `system`. */
function attributionBlock(text: string = MESSAGES_ATTRIBUTION) {
  return { type: "text", text };
}

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

describe("attribution", () => {
  /**
   * Goldens, not round-trips. Each value below was computed independently from
   * the algorithm's definition, so a refactor that changes the fingerprint
   * fails here instead of quietly presenting a build that never shipped.
   */
  it("reproduces the published fingerprint vector", async () => {
    expect(await computeFingerprint("x", "2.1.220")).toBe("04c");
  });

  it("substitutes '0' for every offset past the end of the message", async () => {
    // "hi" is shorter than the first sampled offset, so it fingerprints as an
    // empty opener does.
    expect(await computeFingerprint("", "2.1.239")).toBe("5e2");
    expect(await computeFingerprint("hi", "2.1.239")).toBe("5e2");
    // Long enough for the first offset only.
    expect(await computeFingerprint("short", "2.1.239")).toBe("c63");
  });

  it("samples a realistic prompt", async () => {
    expect(
      await computeFingerprint(
        "Refactor the auth middleware so the token check happens before rate limiting.",
        "2.1.239",
      ),
    ).toBe("1c8");
  });

  it("indexes UTF-16 code units, as the real client does", async () => {
    // The client is JavaScript, where `text[i]` is a UTF-16 code unit. Both
    // reference implementations of this algorithm are Go and index by rune or by
    // byte instead; all three agree on ASCII and diverge here.
    //
    // This opener is deliberately the awkward case: offset 4 lands *inside* a
    // surrogate pair, so the sampled character is a lone high surrogate. Encoding
    // that to UTF-8 substitutes U+FFFD, which is what the digest actually sees --
    // so the answer is not reachable by sampling code points (cb6) and not
    // reachable by preserving the raw surrogate bytes either (4fd, which only a
    // surrogate-passing encoder would produce).
    expect(
      await computeFingerprint(
        "\u{1f389}\u{1f389}\u{1f389} ship it now, please review the diff",
        "2.1.239",
      ),
    ).toBe("b2c");
    // A BMP non-ASCII opener, where byte-indexing is the one that diverges.
    expect(await computeFingerprint("请帮我分析这个仓库的构建系统", "2.1.239")).toBe("a9c");
  });

  it("changes with the CLI version", async () => {
    expect(await computeFingerprint("x", "2.1.239")).not.toBe(
      await computeFingerprint("x", "2.1.220"),
    );
  });

  it("emits the block without cch", async () => {
    // Current clients stopped sending it, so reproducing it would diverge from
    // real traffic rather than match it.
    const text = await buildAttributionText(MESSAGES, "2.1.239", "cli");

    expect(text).toBe(MESSAGES_ATTRIBUTION);
    expect(text).not.toContain("cch=");
  });

  it("reads the first user message and stops there", () => {
    expect(
      extractFirstUserText([
        { role: "assistant", content: "ignored" },
        { role: "user", content: "first" },
        { role: "user", content: "second" },
      ]),
    ).toBe("first");
  });

  it("reads the leading text block of a structured message", () => {
    expect(
      extractFirstUserText([
        {
          role: "user",
          content: [
            { type: "image", source: {} },
            { type: "text", text: "after the image" },
          ],
        },
      ]),
    ).toBe("after the image");
  });

  it("yields the empty string for an opener with no text", () => {
    // Falling through to a later message would make the fingerprint move
    // between turns, which is the property this reading exists to protect.
    expect(
      extractFirstUserText([
        { role: "user", content: [{ type: "image", source: {} }] },
        { role: "user", content: "later text" },
      ]),
    ).toBe("");
    expect(extractFirstUserText(undefined)).toBe("");
    expect(extractFirstUserText([])).toBe("");
  });

  it("recognises a block already in place, including a padded one", () => {
    expect(isAttributionText(MESSAGES_ATTRIBUTION)).toBe(true);
    expect(isAttributionText("  \n\t" + MESSAGES_ATTRIBUTION)).toBe(true);
    expect(isAttributionText("You are Claude Code")).toBe(false);
    expect(isAttributionText(undefined)).toBe(false);
  });

  it("leads the survivors and drops a caller's own block", () => {
    const applied = applyAttribution(
      [
        { type: "text", text: "x-anthropic-billing-header: cc_version=1.0.0.zzz; cc_entrypoint=cli;" },
        { type: "text", text: "keep me" },
      ],
      MESSAGES_ATTRIBUTION,
    );

    expect(applied).toEqual([attributionBlock(), { type: "text", text: "keep me" }]);
  });

  it("drops a blank string system rather than promoting an empty block", () => {
    expect(applyAttribution("   ", MESSAGES_ATTRIBUTION)).toEqual([attributionBlock()]);
  });

  it("is idempotent", () => {
    const once = applyAttribution([{ type: "text", text: "keep me" }], MESSAGES_ATTRIBUTION);
    const twice = applyAttribution(once, MESSAGES_ATTRIBUTION);

    expect(twice).toEqual(once);
  });
});

describe("body handling", () => {
  it("leads the caller's system array with the attribution block", async () => {
    // The block is what admits the request: without it the upstream refuses
    // before a model is reached, observed as 503 on an otherwise correct
    // request.
    const system = [{ type: "text", text: "be terse" }];
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", system, messages: MESSAGES })).body,
    );

    expect(body.system).toEqual([attributionBlock(), ...system]);
  });

  it("promotes a string system prompt so the block can lead it", async () => {
    // Equivalent to the API, and the upstream check only reads the array form.
    const body = decode(
      (
        await shape({
          model: "claude-sonnet-4-6",
          system: "be terse",
          messages: MESSAGES,
        })
      ).body,
    );

    expect(body.system).toEqual([attributionBlock(), { type: "text", text: "be terse" }]);
  });

  it("writes the block even when the caller sent no system prompt", async () => {
    // Admission is all-or-nothing upstream, so there is no request this Worker
    // can usefully send without it.
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", messages: MESSAGES })).body,
    );

    expect(body.system).toEqual([attributionBlock()]);
  });

  it("adds no identity sentence", async () => {
    // An instruction would change what the model answers. A probe carrying the
    // block *without* the sentence was admitted and answered normally, so the
    // sentence buys no admission that would justify the cost.
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", messages: MESSAGES })).body,
    );

    expect(JSON.stringify(body.system)).not.toContain("You are Claude Code");
  });

  it("keeps the caller's own blocks and their cache breakpoints in order", async () => {
    const system = [
      { type: "text", text: "first" },
      { type: "text", text: "second", cache_control: { type: "ephemeral" } },
    ];
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", system, messages: MESSAGES })).body,
    );

    expect(body.system).toEqual([attributionBlock(), ...system]);
  });

  it("carries no cache_control of its own", async () => {
    // The real client's attribution block is bare; the breakpoint belongs to
    // whatever follows it.
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", messages: MESSAGES })).body,
    );
    const blocks = body.system as Record<string, unknown>[];

    expect(blocks[0]?.cache_control).toBeUndefined();
  });

  it("replaces a caller's own attribution block rather than stacking one", async () => {
    // Keeping both would present two builds behind one credential, and it is
    // what makes a second hop converge.
    const system = [
      {
        type: "text",
        text: "x-anthropic-billing-header: cc_version=1.0.0.zzz; cc_entrypoint=cli;",
      },
      { type: "text", text: "be terse" },
    ];
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", system, messages: MESSAGES })).body,
    );

    expect(body.system).toEqual([attributionBlock(), { type: "text", text: "be terse" }]);
  });

  it("fingerprints the first user message, not the latest", async () => {
    // This is what keeps the block -- and therefore the cached prefix -- stable
    // across the turns of one conversation.
    const opener = {
      role: "user",
      content:
        "Refactor the auth middleware so the token check happens before rate limiting.",
    };
    const first = decode((await shape({ model: "claude-sonnet-4-6", messages: [opener] })).body);
    const later = decode(
      (
        await shape({
          model: "claude-sonnet-4-6",
          messages: [
            opener,
            { role: "assistant", content: "ok" },
            { role: "user", content: "now do the same for the logging layer" },
          ],
        })
      ).body,
    );

    const lead = (payload: Record<string, unknown>) =>
      (payload.system as Record<string, unknown>[])[0]?.text;

    expect(lead(first)).toBe(
      "x-anthropic-billing-header: cc_version=2.1.239.1c8; cc_entrypoint=cli;",
    );
    expect(lead(later)).toBe(lead(first));
  });

  it("leaves tools untouched", async () => {
    const tools = [{ name: "read", description: "x", input_schema: { type: "object" } }];
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", tools, messages: MESSAGES })).body,
    );

    expect(body.tools).toEqual(tools);
  });

  it("never adds context_management", async () => {
    // `clear_thinking_20251015` tells the API to drop thinking blocks. On a
    // caller that owns its thinking history that is silent data loss it never
    // asked for.
    const body = decode(
      (
        await shape({
          model: "claude-sonnet-4-6",
          thinking: { type: "enabled", budget_tokens: 1024 },
          messages: MESSAGES,
        })
      ).body,
    );

    expect(body.context_management).toBeUndefined();
  });

  it("forwards a caller's own context_management", async () => {
    const managed = { edits: [{ type: "clear_thinking_20251015", keep: "all" }] };
    const body = decode(
      (
        await shape({
          model: "claude-sonnet-4-6",
          thinking: { type: "enabled" },
          context_management: managed,
          messages: MESSAGES,
        })
      ).body,
    );

    expect(body.context_management).toEqual(managed);
  });

  it("preserves every field it does not own", async () => {
    // `metadata` and `system` are the two this cloak writes; everything else
    // must survive with its value intact.
    const original = {
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      temperature: 0.3,
      stream: true,
      messages: MESSAGES,
    };
    const body = decode((await shape(original)).body);
    const { metadata, system, ...rest } = body;

    expect(metadata).toBeDefined();
    expect(system).toEqual([attributionBlock()]);
    expect(rest).toEqual(original);
  });

  it("stamps the client identity into metadata", async () => {
    const metadata = decode(
      (await shape({ model: "claude-sonnet-4-6", messages: MESSAGES })).body,
    ).metadata as Record<string, unknown>;

    expect(JSON.parse(String(metadata.user_id)).device_id).toBe(IDENTITY.deviceId);
  });

  it("keeps a caller's other metadata keys", async () => {
    // `user_id` is the only metadata field this cloak owns.
    const metadata = decode(
      (
        await shape({
          model: "claude-sonnet-4-6",
          metadata: { trace: "abc" },
          messages: MESSAGES,
        })
      ).body,
    ).metadata as Record<string, unknown>;

    expect(metadata.trace).toBe("abc");
  });

  it("reports capabilities from the caller's body", async () => {
    // The beta header is derived from this, so it must describe the request
    // that is actually sent -- no more and no less than the caller asked for.
    const result = await shape({
      model: "claude-sonnet-4-6",
      thinking: { type: "enabled" },
      tools: [{ name: "read" }],
      messages: MESSAGES,
    });

    expect(result.capabilities.hasThinking).toBe(true);
    expect(result.capabilities.hasTools).toBe(true);
    // False because nothing synthesizes it any more; announcing the beta
    // without the field would be both a fingerprint and an upstream 400.
    expect(result.capabilities.hasContextManagement).toBe(false);
  });

  it("leaves a non-JSON body untouched", async () => {
    const raw = new TextEncoder().encode("not json at all");
    const result = await transformBody(raw, {
      endpoint: "messages",
      identity: IDENTITY,
      profile: DEFAULT_CLOAK_PROFILE,
      contentType: "application/octet-stream",
    });

    expect(result.body).toBe(raw);
    // Nothing is claimed for a body this module cannot read.
    expect(result.capabilities.hasTools).toBe(false);
  });

  it("leaves unparseable JSON untouched", async () => {
    const raw = new TextEncoder().encode("{broken");
    const result = await transformBody(raw, {
      endpoint: "messages",
      identity: IDENTITY,
      profile: DEFAULT_CLOAK_PROFILE,
      contentType: "application/json",
    });

    expect(result.body).toBe(raw);
  });

  it("leaves an unrecognised endpoint untouched", async () => {
    // An unfamiliar shape may carry neither `system` nor `metadata`; writing
    // either would be inventing a schema.
    const raw = encode({ model: "claude-sonnet-4-6" });

    expect((await shape({ model: "claude-sonnet-4-6" }, "other")).body).toEqual(raw);
  });

  it("gives count_tokens the block as well", async () => {
    // The upstream check waves that endpoint through on user-agent alone, but
    // the count has to describe the `/v1/messages` request that follows, and
    // that request will carry the block.
    const body = decode(
      (await shape({ model: "claude-sonnet-4-6", messages: MESSAGES }, "count_tokens")).body,
    );

    expect(body.system).toEqual([attributionBlock()]);
  });

  it("is idempotent", async () => {
    const once = (
      await shape({
        model: "claude-sonnet-4-6",
        system: "be terse",
        thinking: { type: "enabled" },
        tools: [{ name: "read" }],
        messages: MESSAGES,
      })
    ).body;

    const twice = (
      await transformBody(once, {
        endpoint: "messages",
        identity: IDENTITY,
        profile: DEFAULT_CLOAK_PROFILE,
        contentType: "application/json",
      })
    ).body;

    expect(new TextDecoder().decode(twice)).toBe(new TextDecoder().decode(once));
  });
});

describe("cloak headers", () => {
  function build(
    incoming: Record<string, string>,
    beta: string | null = null,
    endpoint: ClaudeEndpoint = "messages",
  ): Headers {
    return buildCloakHeaders(new Headers(incoming), DEFAULT_CLOAK_PROFILE, beta, endpoint);
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
    // The CLI constructs its client with dangerouslyAllowBrowser: true, so the
    // SDK emits this on every request. Omitting it is the tell, not sending it.
    expect(headers.get("anthropic-dangerous-direct-browser-access")).toBe("true");
    // 600000ms client default -> trunc(600000/1000).
    expect(headers.get("x-stainless-timeout")).toBe("600");
  });

  it("omits the timeout header on count_tokens only", () => {
    // messages.create always resolves a timeout, so the SDK's conditional always
    // fires; count_tokens passes no timeout at all, so the header is absent. The
    // asymmetry is the authentic shape.
    expect(build({}, null, "messages").get("x-stainless-timeout")).toBe("600");
    expect(build({}, null, "count_tokens").has("x-stainless-timeout")).toBe(false);
  });

  it("rebuilds the timeout rather than forwarding the caller's", () => {
    const headers = build({ "x-stainless-timeout": "30" });

    expect(headers.get("x-stainless-timeout")).toBe("600");
  });

  it("drops the helper headers it cannot honestly reproduce", () => {
    // Emitted only when a helper symbol is attached to the request, which this
    // Worker cannot observe; a fixed value would be a tell in either direction.
    const headers = build({
      "x-stainless-helper": "messages.stream",
      "x-stainless-helper-method": "stream",
    });

    expect(headers.has("x-stainless-helper")).toBe(false);
    expect(headers.has("x-stainless-helper-method")).toBe(false);
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
    const twice = buildCloakHeaders(
      once,
      DEFAULT_CLOAK_PROFILE,
      "claude-code-20250219",
      "messages",
    );

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

  it("derives the beta header from the body, not from the caller", async () => {
    // The caller claims tool use on a request with no tools; the header must
    // describe the body that is actually sent.
    const projected = await projectClaudeRequest(
      request({ model: "claude-sonnet-4-6", messages: MESSAGES }, {
        "anthropic-beta": "advanced-tool-use-2025-11-20",
      }),
      encode({ model: "claude-sonnet-4-6", messages: MESSAGES }),
      {},
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
    );

    expect(projected.headers.get("anthropic-beta")).toContain(TOKEN_COUNTING_BETA);
  });

  it("writes a stable identity into the body", async () => {
    const body = { model: "claude-sonnet-4-6", messages: MESSAGES };
    const first = await projectClaudeRequest(request(body), encode(body), {});
    const second = await projectClaudeRequest(request(body), encode(body), {});

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
    );
    const b = await projectClaudeRequest(
      request(body, { "x-api-key": "key-b" }),
      encode(body),
      {},
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
    const once = await projectClaudeRequest(request(body), encode(body), {});

    const replay = new Request("https://w.example/api.anthropic.com/v1/messages", {
      method: "POST",
      headers: once.headers,
      body: new TextDecoder().decode(once.body),
    });
    const twice = await projectClaudeRequest(replay, once.body, {});

    expect(new TextDecoder().decode(twice.body)).toBe(
      new TextDecoder().decode(once.body),
    );
    expect(twice.headers.get("anthropic-beta")).toBe(
      once.headers.get("anthropic-beta"),
    );
    expect(twice.headers.get("user-agent")).toBe(once.headers.get("user-agent"));
  });
});
