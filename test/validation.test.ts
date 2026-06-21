import { describe, expect, test } from "bun:test";

import {
  ALLOWED_KEYCODES,
  encodeAdbText,
  isRateLimited,
  parseAdbDevicePorts,
  parseAdbShellCommand,
  pickEmulatorPort,
  redactSensitive,
  validateActivity,
  validateAvdName,
  validatePackage,
  validatePullDevicePath,
  validateSerial,
  xDisplaySocket,
} from "../src/validation.js";

// Expected values are derived by reasoning about the rules these helpers
// enforce (the security allowlists, the ADB encoding spec, the sliding window),
// NOT by re-running the implementation — so a logic regression is caught.

describe("validatePackage", () => {
  test("accepts a well-formed dotted package", () => {
    expect(() => validatePackage("com.example.app")).not.toThrow();
    expect(() => validatePackage("a.b")).not.toThrow();
  });

  test("rejects a single segment (no dot)", () => {
    // PACKAGE_REGEX requires at least one (\.segment) group.
    expect(() => validatePackage("android")).toThrow("Invalid package name");
  });

  test("rejects a leading digit in a segment", () => {
    expect(() => validatePackage("com.1example.app")).toThrow();
    expect(() => validatePackage("9com.example")).toThrow();
  });

  test("rejects shell metacharacters (injection guard)", () => {
    expect(() => validatePackage("com.example;rm -rf")).toThrow();
    expect(() => validatePackage("com.example/Activity")).toThrow();
  });
});

describe("validateActivity", () => {
  test("accepts a leading-dot relative activity and a fully-qualified one", () => {
    expect(() => validateActivity(".MainActivity")).not.toThrow();
    expect(() => validateActivity("com.example.MainActivity")).not.toThrow();
  });

  test("rejects names starting with a digit or containing a slash", () => {
    expect(() => validateActivity("1Main")).toThrow();
    expect(() => validateActivity("com/example")).toThrow();
  });
});

describe("validateSerial", () => {
  test("accepts emulator and usb-style serials", () => {
    expect(() => validateSerial("emulator-5554")).not.toThrow();
    expect(() => validateSerial("192.168.1.5:5555")).not.toThrow();
    expect(() => validateSerial("ABCD1234")).not.toThrow();
  });

  test("rejects empty, leading-dash, and over-64-char serials", () => {
    expect(() => validateSerial("")).toThrow("Invalid device serial");
    expect(() => validateSerial("-rf")).toThrow(); // leading dash → arg-injection guard
    expect(() => validateSerial("a".repeat(65))).toThrow();
  });

  test("accepts exactly 64 chars (boundary) but rejects spaces", () => {
    expect(() => validateSerial("a".repeat(64))).not.toThrow();
    expect(() => validateSerial("dev ice")).toThrow();
  });
});

describe("validateAvdName", () => {
  test("accepts names starting with a letter, digit, or underscore", () => {
    expect(() => validateAvdName("mcp_emulator")).not.toThrow();
    expect(() => validateAvdName("_avd")).not.toThrow();
    expect(() => validateAvdName("9pixel")).not.toThrow();
  });

  test("rejects a leading dash, dot-leading, empty, and over-long names", () => {
    expect(() => validateAvdName("-avd")).toThrow("Invalid AVD name"); // dash not allowed at start
    expect(() => validateAvdName(".avd")).toThrow(); // dot not in the allowed first-char class
    expect(() => validateAvdName("")).toThrow();
    expect(() => validateAvdName("a".repeat(65))).toThrow();
  });
});

describe("validatePullDevicePath", () => {
  const prefixes = ["/sdcard/Download/", "/data/local/tmp/"] as const;

  test("accepts a path under an allowed prefix", () => {
    expect(() => validatePullDevicePath("/sdcard/Download/out.txt", prefixes)).not.toThrow();
  });

  test("rejects path traversal regardless of prefix", () => {
    expect(() => validatePullDevicePath("/sdcard/Download/../../etc/passwd", prefixes)).toThrow(
      "Path traversal not allowed",
    );
  });

  test("rejects a path outside every allowed prefix", () => {
    expect(() => validatePullDevicePath("/system/bin/sh", prefixes)).toThrow("Pull restricted to");
  });
});

describe("xDisplaySocket", () => {
  test("maps :0 to X0 and strips the screen suffix", () => {
    expect(xDisplaySocket(":0")).toBe("/tmp/.X11-unix/X0");
    expect(xDisplaySocket(":7")).toBe("/tmp/.X11-unix/X7");
    expect(xDisplaySocket(":0.1")).toBe("/tmp/.X11-unix/X0"); // ".1" screen suffix dropped
  });
});

describe("parseAdbDevicePorts", () => {
  test("extracts even console ports from `adb devices` output", () => {
    const out = [
      "List of devices attached",
      "emulator-5554\tdevice",
      "emulator-5556\toffline",
      "192.168.1.5:5555\tdevice", // not an emulator line → ignored
      "",
    ].join("\n");
    expect(parseAdbDevicePorts(out)).toEqual(new Set([5554, 5556]));
  });

  test("returns an empty set when no emulators are present", () => {
    expect(parseAdbDevicePorts("List of devices attached\n")).toEqual(new Set());
  });
});

describe("pickEmulatorPort", () => {
  test("returns 5554 when nothing is used", () => {
    expect(pickEmulatorPort(new Set())).toBe(5554);
  });

  test("skips used ports and returns the next free even port", () => {
    expect(pickEmulatorPort(new Set([5554, 5556]))).toBe(5558);
  });

  test("throws once the whole 5554-5584 range is exhausted", () => {
    const all = new Set<number>();
    for (let p = 5554; p <= 5584; p += 2) all.add(p);
    expect(() => pickEmulatorPort(all)).toThrow("no free emulator console port");
  });
});

describe("redactSensitive", () => {
  test("redacts a key=value secret but preserves the key and separator", () => {
    expect(redactSensitive("store_password=hunter2")).toBe("store_password=[REDACTED]");
    expect(redactSensitive("api_key: abc123")).toBe("api_key:[REDACTED]");
  });

  test("redacts bare keystore/credential file paths", () => {
    // The KEYFILE pattern anchors on a \b word boundary, so it begins matching
    // after the leading "/" (a non-word char) — the path body + extension is
    // redacted, the separator slash stays. That is enough to scrub the secret.
    expect(redactSensitive("Could not read /home/u/release.jks")).toBe(
      "Could not read /[REDACTED-KEYFILE]",
    );
    expect(redactSensitive("signing keystore app.keystore failed")).toBe(
      "signing keystore [REDACTED-KEYFILE] failed",
    );
  });

  test("leaves non-sensitive text untouched", () => {
    expect(redactSensitive("BUILD SUCCESSFUL in 12s")).toBe("BUILD SUCCESSFUL in 12s");
  });
});

describe("encodeAdbText", () => {
  test("encodes spaces as %s", () => {
    expect(encodeAdbText("hello world")).toBe("hello%sworld");
  });

  test("doubles a literal percent before space-encoding", () => {
    // "50% off" → % doubled first → "50%% off" → space → "50%%%soff"
    expect(encodeAdbText("50% off")).toBe("50%%%soff");
  });

  test("backslash-escapes shell-special characters", () => {
    expect(encodeAdbText("a&b")).toBe("a\\&b");
    expect(encodeAdbText("$(x)")).toBe("\\$\\(x\\)");
  });

  test("leaves plain alphanumerics unchanged", () => {
    expect(encodeAdbText("Hello123")).toBe("Hello123");
  });
});

describe("ALLOWED_KEYCODES", () => {
  test("maps known safe keys to their Android keycodes", () => {
    expect(ALLOWED_KEYCODES["BACK"]).toBe("4");
    expect(ALLOWED_KEYCODES["HOME"]).toBe("3");
    expect(ALLOWED_KEYCODES["ENTER"]).toBe("66");
  });

  test("does not expose dangerous keys (POWER/REBOOT/SLEEP)", () => {
    expect(ALLOWED_KEYCODES["POWER"]).toBeUndefined();
    expect(ALLOWED_KEYCODES["REBOOT"]).toBeUndefined();
    expect(ALLOWED_KEYCODES["SLEEP"]).toBeUndefined();
  });
});

describe("parseAdbShellCommand", () => {
  test("pm clear → validated package args", () => {
    expect(parseAdbShellCommand("pm clear com.example.app")).toEqual([
      "pm",
      "clear",
      "com.example.app",
    ]);
  });

  test("am force-stop → validated package args", () => {
    expect(parseAdbShellCommand("am force-stop com.example.app")).toEqual([
      "am",
      "force-stop",
      "com.example.app",
    ]);
  });

  test("airplane-mode enable/disable", () => {
    expect(parseAdbShellCommand("cmd connectivity airplane-mode enable")).toEqual([
      "cmd",
      "connectivity",
      "airplane-mode",
      "enable",
    ]);
    expect(parseAdbShellCommand("cmd connectivity airplane-mode disable")).toEqual([
      "cmd",
      "connectivity",
      "airplane-mode",
      "disable",
    ]);
  });

  test("settings get/put with valid namespace + key", () => {
    expect(parseAdbShellCommand("settings get global airplane_mode_on")).toEqual([
      "settings",
      "get",
      "global",
      "airplane_mode_on",
    ]);
    expect(parseAdbShellCommand("settings put system screen_brightness 120")).toEqual([
      "settings",
      "put",
      "system",
      "screen_brightness",
      "120",
    ]);
  });

  test("getprop with a dotted property", () => {
    expect(parseAdbShellCommand("getprop ro.build.version.sdk")).toEqual([
      "getprop",
      "ro.build.version.sdk",
    ]);
  });

  test("collapses extra whitespace before matching", () => {
    expect(parseAdbShellCommand("  pm   clear   com.example.app  ")).toEqual([
      "pm",
      "clear",
      "com.example.app",
    ]);
  });

  test("rejects an empty command", () => {
    expect(() => parseAdbShellCommand("   ")).toThrow("Empty command");
  });

  test("rejects any command not on the allowlist", () => {
    expect(() => parseAdbShellCommand("rm -rf /sdcard")).toThrow("Command not allowed");
    expect(() => parseAdbShellCommand("pm install foo.apk")).toThrow("Command not allowed");
    expect(() => parseAdbShellCommand("am start -n com.x/.Main")).toThrow("Command not allowed");
  });

  test("rejects airplane-mode with an unknown action", () => {
    expect(() => parseAdbShellCommand("cmd connectivity airplane-mode toggle")).toThrow(
      "Command not allowed",
    );
  });

  test("rejects a bad settings namespace", () => {
    expect(() => parseAdbShellCommand("settings get evil some_key")).toThrow(
      "Invalid settings namespace",
    );
  });

  test("rejects a settings key with disallowed characters", () => {
    expect(() => parseAdbShellCommand("settings get global bad-key")).toThrow(
      "Invalid settings key",
    );
  });

  test("rejects a settings put value with disallowed characters", () => {
    expect(() => parseAdbShellCommand("settings put system key val;rm")).toThrow(
      "Invalid settings value",
    );
  });

  test("rejects an injection attempt smuggled through the package arg", () => {
    expect(() => parseAdbShellCommand("pm clear com.x;reboot")).toThrow("Invalid package name");
  });

  test("rejects a getprop property with disallowed characters", () => {
    expect(() => parseAdbShellCommand("getprop ro;reboot")).toThrow("Invalid property name");
  });
});

describe("isRateLimited (sliding window)", () => {
  const LIMIT = 3;
  const WINDOW = 1000;

  test("allows up to LIMIT requests within the window, then blocks", () => {
    const ts: number[] = [];
    expect(isRateLimited(ts, 0, LIMIT, WINDOW)).toBe(false); // 1
    expect(isRateLimited(ts, 1, LIMIT, WINDOW)).toBe(false); // 2
    expect(isRateLimited(ts, 2, LIMIT, WINDOW)).toBe(false); // 3
    expect(isRateLimited(ts, 3, LIMIT, WINDOW)).toBe(true); // 4 → blocked
    expect(ts.length).toBe(3); // a blocked request is NOT recorded
  });

  test("evicts entries older than the window so capacity recovers", () => {
    const ts = [0, 1, 2]; // three requests at t=0,1,2
    // At t=1001, the t=0 entry (< 1001-1000=1) is evicted → only 2 remain → allowed.
    expect(isRateLimited(ts, 1001, LIMIT, WINDOW)).toBe(false);
    expect(ts).toEqual([1, 2, 1001]);
  });

  test("an exactly-window-old entry is kept (strict < boundary)", () => {
    const ts = [0, 0, 0]; // full at t=0
    // At t=1000: 0 < 1000-1000=0 is false → none evicted → still full → blocked.
    expect(isRateLimited(ts, 1000, LIMIT, WINDOW)).toBe(true);
  });
});
