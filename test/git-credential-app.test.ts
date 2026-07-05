import { describe, expect, test } from "bun:test";

import {
  base64UrlEncode,
  buildAppJwtSigningInput,
  parseGitCredentialRequest,
} from "../src/validation.js";

// The IO (stdin, key signing, fetch, stdout) lives in src/git-credential-app.ts and is exercised
// by the on-deploy private-repo sync; these cover the pure, security-relevant parsing/encoding.

describe("parseGitCredentialRequest", () => {
  test("parses key=value lines into a map", () => {
    const r = parseGitCredentialRequest("protocol=https\nhost=github.com\npath=soult-io/x.git\n");
    expect(r).toEqual({ protocol: "https", host: "github.com", path: "soult-io/x.git" });
  });

  test("stops at the first blank line (end of the request — ignores anything after)", () => {
    const r = parseGitCredentialRequest("host=github.com\n\nhost=evil.com\n");
    expect(r["host"]).toBe("github.com");
  });

  test("splits on the FIRST '=' so values may contain '='", () => {
    expect(parseGitCredentialRequest("password=a=b=c\n")["password"]).toBe("a=b=c");
  });

  test("ignores malformed lines (no '=' / empty key)", () => {
    expect(parseGitCredentialRequest("nonsense\n=noKey\nhost=github.com\n")).toEqual({
      host: "github.com",
    });
  });
});

describe("base64UrlEncode", () => {
  test("is url-safe (+/ -> -_) and unpadded", () => {
    // bytes fb ff bf -> standard base64 "+/+/" -> url-safe "-_-_", no "=" padding
    expect(base64UrlEncode(Buffer.from([0xfb, 0xff, 0xbf]))).toBe("-_-_");
  });

  test("encodes a string as utf8, unpadded", () => {
    expect(base64UrlEncode("hi")).toBe("aGk"); // "aGk=" without padding
  });
});

describe("buildAppJwtSigningInput", () => {
  test("produces exactly two base64url segments with the App JWT header + claims", () => {
    const now = 1_700_000_000;
    const input = buildAppJwtSigningInput("4221027", now);
    const parts = input.split(".");
    expect(parts.length).toBe(2);
    const header = JSON.parse(Buffer.from(parts[0] as string, "base64url").toString());
    const payload = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString());
    expect(header).toEqual({ alg: "RS256", typ: "JWT" });
    // iat backdated 60s for skew; exp +540s (< GitHub's 10-min max); iss = App ID.
    expect(payload).toEqual({ iat: now - 60, exp: now + 540, iss: "4221027" });
  });
});
