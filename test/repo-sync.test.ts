import { describe, expect, test } from "bun:test";

import { parseRepoSpec, validateGitRef } from "../src/validation.js";

// Expected values are derived from the documented rules — the org guard, the
// repo-name/ref whitelists — NOT by re-running the implementation, so a logic
// regression on this RCE-surface input path is caught.

describe("parseRepoSpec", () => {
  test("parses a valid owner/name into url + single-segment dir", () => {
    const spec = parseRepoSpec("soult-io/embara-android", "soult-io");
    expect(spec).toEqual({
      owner: "soult-io",
      name: "embara-android",
      url: "https://github.com/soult-io/embara-android.git",
      dir: "embara-android",
    });
  });

  test("accepts names with dots, underscores, and hyphens", () => {
    expect(parseRepoSpec("soult-io/home-net.android_v2", "soult-io").name).toBe(
      "home-net.android_v2",
    );
  });

  test("enforces the org guard — rejects a different owner", () => {
    expect(() => parseRepoSpec("evil/payload-android", "soult-io")).toThrow(/owner must be/);
  });

  test("honours the allowedOwner argument (not hard-coded)", () => {
    expect(parseRepoSpec("acme/widget", "acme").owner).toBe("acme");
    expect(() => parseRepoSpec("acme/widget", "soult-io")).toThrow(/owner must be/);
  });

  test("rejects a missing slash (no owner)", () => {
    expect(() => parseRepoSpec("embara-android", "soult-io")).toThrow(/<owner>\/<name>/);
  });

  test("rejects extra path segments (defeats a nested-path injection)", () => {
    expect(() => parseRepoSpec("soult-io/a/b", "soult-io")).toThrow(/<owner>\/<name>/);
  });

  test("rejects path-traversal names", () => {
    expect(() => parseRepoSpec("soult-io/..", "soult-io")).toThrow(/Invalid repo name/);
    expect(() => parseRepoSpec("soult-io/.", "soult-io")).toThrow(/Invalid repo name/);
  });

  test("rejects names with shell/space/metacharacters", () => {
    for (const bad of ["a b", "a;b", "a$b", "a|b", "a`b", "a\\b", "a/b"]) {
      expect(() => parseRepoSpec(`soult-io/${bad}`, "soult-io")).toThrow();
    }
  });

  test("rejects an empty name", () => {
    expect(() => parseRepoSpec("soult-io/", "soult-io")).toThrow(/Invalid repo name/);
  });

  test("does not embed credentials in the clone URL", () => {
    expect(parseRepoSpec("soult-io/x", "soult-io").url).toBe("https://github.com/soult-io/x.git");
  });
});

describe("validateGitRef", () => {
  test("accepts branches, nested branches, tags, and a full SHA", () => {
    for (const ok of [
      "main",
      "feat/ref-driven-repo-sync",
      "release/1.0",
      "v1.2.3",
      "0123456789abcdef0123456789abcdef01234567",
    ]) {
      expect(() => validateGitRef(ok)).not.toThrow();
    }
  });

  test("rejects empty", () => {
    expect(() => validateGitRef("")).toThrow(/Invalid git ref/);
  });

  test("rejects a leading dash (arg injection)", () => {
    expect(() => validateGitRef("--upload-pack=evil")).toThrow(/Invalid git ref/);
  });

  test("rejects double-dot and trailing slash", () => {
    expect(() => validateGitRef("a..b")).toThrow(/Invalid git ref/);
    expect(() => validateGitRef("feat/")).toThrow(/Invalid git ref/);
  });

  test("rejects ref metacharacters git itself forbids", () => {
    for (const bad of ["a b", "a~b", "a^b", "a:b", "a?b", "a*b", "a[b", "a\\b", "a;b", "a$(x)"]) {
      expect(() => validateGitRef(bad)).toThrow(/Invalid git ref/);
    }
  });

  test("rejects an over-length ref", () => {
    expect(() => validateGitRef("a".repeat(201))).toThrow(/Invalid git ref/);
  });
});
