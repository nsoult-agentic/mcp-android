import { describe, expect, test } from "bun:test";

import { ALLOWED_SDK_PACKAGE_PREFIXES, validateSdkPackage } from "../src/validation.js";

describe("validateSdkPackage", () => {
  test("accepts the package types a build needs to auto-provision", () => {
    expect(() => validateSdkPackage("platforms;android-37.0")).not.toThrow();
    expect(() => validateSdkPackage("platforms;android-37.1")).not.toThrow();
    expect(() => validateSdkPackage("build-tools;35.0.0")).not.toThrow();
    expect(() => validateSdkPackage("system-images;android-34;google_apis;x86_64")).not.toThrow();
    // ABI with a dash is a real coordinate and must be allowed.
    expect(() =>
      validateSdkPackage("system-images;android-34;google_apis_playstore;arm64-v8a"),
    ).not.toThrow();
  });

  test("rejects package types outside the allowlist", () => {
    // "platform-tools" starts like "platforms" but is a different, non-allowlisted package.
    expect(() => validateSdkPackage("platform-tools")).toThrow(/disallowed SDK package/);
    expect(() => validateSdkPackage("emulator")).toThrow(/disallowed SDK package/);
    expect(() => validateSdkPackage("ndk;26.1.10909125")).toThrow(/disallowed SDK package/);
    expect(() => validateSdkPackage("cmdline-tools;latest")).toThrow(/disallowed SDK package/);
  });

  test("rejects a leading dash (arg injection)", () => {
    expect(() => validateSdkPackage("-platforms;android-37.0")).toThrow();
    expect(() => validateSdkPackage("--uninstall")).toThrow();
  });

  test("rejects shell metacharacters and whitespace", () => {
    expect(() => validateSdkPackage("platforms;android-37.0; rm -rf /")).toThrow();
    expect(() => validateSdkPackage("platforms;android-37.0 && reboot")).toThrow();
    expect(() => validateSdkPackage("platforms;android-37.0|cat")).toThrow();
    expect(() => validateSdkPackage("$(reboot)")).toThrow();
    expect(() => validateSdkPackage("build-tools;`id`")).toThrow();
  });

  test("rejects trailing newline / carriage return (charset-regex $ edge)", () => {
    expect(() => validateSdkPackage("platforms;android-37.0\n")).toThrow();
    expect(() => validateSdkPackage("platforms;android-37.0\r")).toThrow();
    expect(() => validateSdkPackage("platforms;android\n-37.0")).toThrow();
  });

  test("rejects path traversal and empty/oversized input", () => {
    expect(() => validateSdkPackage("system-images;../../etc/passwd")).toThrow();
    expect(() => validateSdkPackage("")).toThrow();
    expect(() => validateSdkPackage(`platforms;${"a".repeat(200)}`)).toThrow();
  });

  test("allowlist is limited to platforms / build-tools / system-images", () => {
    expect([...ALLOWED_SDK_PACKAGE_PREFIXES]).toEqual([
      "platforms;",
      "build-tools;",
      "system-images;",
    ]);
  });
});
