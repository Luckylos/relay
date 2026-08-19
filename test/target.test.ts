import { describe, expect, it } from "vitest";
import { parseTarget, TargetError } from "../src/target";

function target(path: string, search = ""): string {
  return parseTarget(new Request(`https://relay.example${path}${search}`)).url.toString();
}

describe("parseTarget", () => {
  it("maps a hostname-only path to the HTTPS root", () => {
    expect(target("/jianzhile.vip")).toBe("https://jianzhile.vip/");
  });

  it("preserves the remaining path and original query", () => {
    const result = parseTarget(
      new Request("https://relay.example/jianzhile.vip/v1/responses?x=1&stream=true"),
    );

    expect(result.hostname).toBe("jianzhile.vip");
    expect(result.pathname).toBe("/v1/responses");
    expect(result.search).toBe("?x=1&stream=true");
    expect(result.url.toString()).toBe(
      "https://jianzhile.vip/v1/responses?x=1&stream=true",
    );
  });

  it("accepts multiple domains without a route table", () => {
    expect(target("/first.example/v1/models")).toBe("https://first.example/v1/models");
    expect(target("/second.example/v1/models")).toBe("https://second.example/v1/models");
  });

  it.each(["", "/", "/https://example.com", "/user:pass@example.com", "/example.com:443"]) (
    "rejects target path %j",
    (path) => {
      expect(() => parseTarget(new Request(`https://relay.example${path}`))).toThrowError(
        expect.objectContaining({ code: "invalid_target" }),
      );
    },
  );

  it.each([
    "/-bad.example/path",
    "/bad_.example/path",
    "/bad..example/path",
    "/bad%2Fexample/path",
    "/bad%40example.com/path",
    "/bad%3A443/path",
  ])("rejects malformed or encoded target host %j", (path) => {
    expect(() => parseTarget(new Request(`https://relay.example${path}`))).toThrow(
      TargetError,
    );
  });

  it("does not let an encoded slash alter the first segment boundary", () => {
    expect(() => parseTarget(new Request("https://relay.example/example.com%2Fv1"))).toThrow(
      TargetError,
    );
  });

  it("preserves encoded slashes in the remaining path", () => {
    expect(target("/example.com/v1%2Fresponses")).toBe(
      "https://example.com/v1%2Fresponses",
    );
  });
});
