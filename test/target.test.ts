import { describe, expect, it } from "vitest";
import { parseTarget, TargetError } from "../src/target";

function target(path: string, search = ""): string {
  return parseTarget(new Request(`https://relay.example${path}${search}`)).url.toString();
}

describe("parseTarget", () => {
  it("maps a hostname-only path to the HTTPS root", () => {
    expect(target("/api.example.com")).toBe("https://api.example.com/");
  });

  it("preserves the remaining path and original query", () => {
    const result = parseTarget(
      new Request("https://relay.example/api.example.com/v1/responses?x=1&stream=true"),
    );

    expect(result.hostname).toBe("api.example.com");
    expect(result.pathname).toBe("/v1/responses");
    expect(result.search).toBe("?x=1&stream=true");
    expect(result.url.toString()).toBe(
      "https://api.example.com/v1/responses?x=1&stream=true",
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

  it("rejects IP literals and local names, not just malformed hostnames", () => {
    // The contract is "any public HTTPS hostname", never "any IP". The relay's
    // post-DNS SSRF policy would also refuse these, but letting them through
    // here would spend relay quota on requests that must always fail and would
    // leave one downstream check as the only defence.
    for (const hostname of [
      "203.0.113.9",
      "127.0.0.1",
      "192.168.1.1",
      "10.0.0.1",
      "169.254.169.254",
      "localhost",
      "LocalHost",
      "localhost.",
      "[2001:db8::1]",
      "0.0.0.0",
    ]) {
      expect(
        () => parseTarget(new Request(`https://relay.example/${hostname}/v1`)),
        hostname,
      ).toThrow(TargetError);
    }
  });

  it("still accepts hostnames with digit-containing labels", () => {
    // Only an all-digit final label is refused; digits elsewhere are ordinary.
    expect(target("/api2.example.com/v1")).toBe("https://api2.example.com/v1");
    expect(target("/1.2.3.example.com/v1")).toBe("https://1.2.3.example.com/v1");
  });
});
