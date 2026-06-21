/**
 * Pure, side-effect-free validation, parsing, and formatting helpers extracted
 * from src/http.ts so they can be unit-tested in isolation. NOTHING in this
 * module touches the filesystem, the network, ADB, or process/module state —
 * importing it must have no observable effect. (Path validators that call
 * realpathSync stay in http.ts; they need a live filesystem.)
 */

// ── Input regexes ──────────────────────────────────────────

const PACKAGE_REGEX = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;
const ACTIVITY_REGEX = /^\.?[a-zA-Z][a-zA-Z0-9_.]*$/;
const SERIAL_REGEX = /^[a-zA-Z0-9.:_-]+$/;
const AVD_NAME_REGEX = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

export function validatePackage(pkg: string): void {
  if (!PACKAGE_REGEX.test(pkg)) {
    throw new Error(`Invalid package name: ${pkg}`);
  }
}

export function validateActivity(activity: string): void {
  if (!ACTIVITY_REGEX.test(activity)) {
    throw new Error(`Invalid activity name: ${activity}`);
  }
}

// Validate device serial — reject empty, leading dash, over-long, non-alphanumeric.
export function validateSerial(serial: string): void {
  if (!serial || serial.length > 64 || serial.startsWith("-") || !SERIAL_REGEX.test(serial)) {
    throw new Error(`Invalid device serial: ${serial}`);
  }
}

// Match the server's serial-validator ethos (no leading dash -> no arg-injection
// into avdmanager/emulator).
export function validateAvdName(name: string): void {
  if (!name || name.length > 64 || !AVD_NAME_REGEX.test(name)) {
    throw new Error(`Invalid AVD name: ${name}`);
  }
}

// Reject path traversal on device paths and confine pulls to an allowlist of prefixes.
export function validatePullDevicePath(
  devicePath: string,
  allowedPrefixes: readonly string[],
): void {
  if (devicePath.includes("..")) {
    throw new Error("Path traversal not allowed");
  }
  const match = allowedPrefixes.some((prefix) => devicePath.startsWith(prefix));
  if (!match) {
    throw new Error(`Pull restricted to: ${allowedPrefixes.join(", ")}`);
  }
}

// ── Display socket derivation ──────────────────────────────

// X socket path for a display string (":0" -> /tmp/.X11-unix/X0; ":0.1" -> X0).
export function xDisplaySocket(display: string): string {
  const n = display.replace(/^:/, "").split(".")[0];
  return `/tmp/.X11-unix/X${n}`;
}

// ── Console-port parsing ───────────────────────────────────

// Parse the even console ports from `adb devices` output (lines like "emulator-5554\tdevice").
export function parseAdbDevicePorts(devicesOutput: string): Set<number> {
  const ports = new Set<number>();
  for (const line of devicesOutput.split("\n")) {
    const m = line.trim().match(/^emulator-(\d+)\b/);
    if (m) ports.add(Number(m[1]));
  }
  return ports;
}

// Lowest free even console port in the emulator range [5554, 5584]; throws if exhausted.
export function pickEmulatorPort(used: Set<number>): number {
  for (let port = 5554; port <= 5584; port += 2) {
    if (!used.has(port)) return port;
  }
  throw new Error("no free emulator console port in 5554-5584");
}

// ── Secret redaction ───────────────────────────────────────

const SENSITIVE_VALUE_PATTERN =
  /(?:password|apiKey|api_key|token|secret|credentials|keystore|store_password|key_password|key_alias)\s*[=:]\s*\S+/gi;
const KEYFILE_PATTERN = /\b[^\s'"]+\.(?:jks|keystore|p12|pfx|pem|key)\b/gi;

// Redact sensitive key=value pairs AND bare keystore/credential file paths from
// text returned to the caller (gradle signing errors print bare *.jks/*.keystore
// paths that a keyword=value regex misses).
export function redactSensitive(s: string): string {
  return s
    .split("\n")
    .map((line) =>
      line
        .replace(SENSITIVE_VALUE_PATTERN, (m) => {
          const sep = m.includes("=") ? "=" : ":";
          return `${m.split(/[=:]/)[0]}${sep}[REDACTED]`;
        })
        .replace(KEYFILE_PATTERN, "[REDACTED-KEYFILE]"),
    )
    .join("\n");
}

// ── ADB `input text` encoding ──────────────────────────────

// ADB `input text` treats spaces as argument separators and interprets certain
// special characters. Encode them before passing to ADB.
const ADB_TEXT_SPECIAL_CHARS = /[()<>|;&*\\~"'`{}$?#[\]!=^]/g;

export function encodeAdbText(text: string): string {
  // Escape literal % first (before space→%s replacement to avoid double-interpretation).
  let encoded = text.replace(/%/g, "%%");
  // Replace spaces with %s (ADB's space encoding).
  encoded = encoded.replace(/ /g, "%s");
  // Escape shell-special chars that ADB interprets (prepend backslash).
  encoded = encoded.replace(ADB_TEXT_SPECIAL_CHARS, (ch) => `\\${ch}`);
  return encoded;
}

// ── Keycode allowlist ──────────────────────────────────────

export const ALLOWED_KEYCODES: Record<string, string> = {
  BACK: "4",
  HOME: "3",
  ENTER: "66",
  TAB: "61",
  DPAD_UP: "19",
  DPAD_DOWN: "20",
  DPAD_LEFT: "21",
  DPAD_RIGHT: "22",
  DEL: "67",
  FORWARD_DEL: "112",
  ESCAPE: "111",
  APP_SWITCH: "187",
  MENU: "82",
  SPACE: "62",
  MOVE_HOME: "122",
  MOVE_END: "123",
};

// ── ADB shell allowlist parser ─────────────────────────────

const SETTINGS_NAMESPACE_REGEX = /^(system|secure|global)$/;
const SETTINGS_KEY_REGEX = /^[a-zA-Z0-9_]+$/;
const GETPROP_REGEX = /^[a-zA-Z0-9.]+$/;

// Each allowlist entry maps a command "shape" (verb + sub-verbs + arg count) to
// a handler that validates the user-supplied args and returns the execFile argv.
// Returning undefined means "shape didn't match, try the next entry"; throwing
// means "shape matched but the args are invalid" (a targeted error to the user).
type ShellHandler = (parts: string[]) => string[] | undefined;

const SHELL_HANDLERS: ShellHandler[] = [
  // pm clear <package>
  (p) => {
    if (p[0] === "pm" && p[1] === "clear" && p.length === 3) {
      validatePackage(p[2] as string);
      return ["pm", "clear", p[2] as string];
    }
    return undefined;
  },
  // am force-stop <package>
  (p) => {
    if (p[0] === "am" && p[1] === "force-stop" && p.length === 3) {
      validatePackage(p[2] as string);
      return ["am", "force-stop", p[2] as string];
    }
    return undefined;
  },
  // cmd connectivity airplane-mode enable|disable
  (p) => {
    if (p[0] === "cmd" && p[1] === "connectivity" && p[2] === "airplane-mode" && p.length === 4) {
      if (p[3] === "enable" || p[3] === "disable") {
        return ["cmd", "connectivity", "airplane-mode", p[3]];
      }
    }
    return undefined;
  },
  // settings get <namespace> <key>
  (p) => {
    if (p[0] === "settings" && p[1] === "get" && p.length === 4) {
      validateSettingsNamespace(p[2] as string);
      validateSettingsToken(p[3] as string, "key");
      return ["settings", "get", p[2] as string, p[3] as string];
    }
    return undefined;
  },
  // settings put <namespace> <key> <value>
  (p) => {
    if (p[0] === "settings" && p[1] === "put" && p.length === 5) {
      validateSettingsNamespace(p[2] as string);
      validateSettingsToken(p[3] as string, "key");
      validateSettingsToken(p[4] as string, "value");
      return ["settings", "put", p[2] as string, p[3] as string, p[4] as string];
    }
    return undefined;
  },
  // getprop <property>
  (p) => {
    if (p[0] === "getprop" && p.length === 2) {
      if (!GETPROP_REGEX.test(p[1] as string)) {
        throw new Error(`Invalid property name: ${p[1]} (alphanumeric and dots only)`);
      }
      return ["getprop", p[1] as string];
    }
    return undefined;
  },
];

/**
 * Parse and validate an ADB shell command against the allowlist.
 * Returns the args array for execFile (after "shell"), or throws on rejection.
 */
export function parseAdbShellCommand(command: string): string[] {
  const parts = command.trim().split(/\s+/);
  if (parts.length === 0 || parts[0] === "") throw new Error("Empty command");

  for (const handler of SHELL_HANDLERS) {
    const argv = handler(parts);
    if (argv) return argv;
  }

  throw new Error(
    "Command not allowed. Allowed commands: " +
      "pm clear <package>, " +
      "am force-stop <package>, " +
      "cmd connectivity airplane-mode enable|disable, " +
      "settings get|put <system|secure|global> <key> [<value>], " +
      "getprop <property>",
  );
}

function validateSettingsNamespace(namespace: string): void {
  if (!SETTINGS_NAMESPACE_REGEX.test(namespace)) {
    throw new Error(`Invalid settings namespace: ${namespace} (allowed: system, secure, global)`);
  }
}

function validateSettingsToken(token: string, label: "key" | "value"): void {
  if (!SETTINGS_KEY_REGEX.test(token)) {
    throw new Error(`Invalid settings ${label}: ${token} (alphanumeric and underscore only)`);
  }
}

// ── Rate limiter ───────────────────────────────────────────

/**
 * Sliding-window rate limiter over a caller-owned timestamp array. Mutates
 * `timestamps` in place: evicts entries older than the window, then either
 * records `now` (returning false = allowed) or rejects (returning true =
 * limited) once `limit` requests are already in the window.
 */
export function isRateLimited(
  timestamps: number[],
  now: number,
  limit: number,
  windowMs: number,
): boolean {
  while (timestamps.length > 0 && (timestamps[0] as number) < now - windowMs) {
    timestamps.shift();
  }
  if (timestamps.length >= limit) return true;
  timestamps.push(now);
  return false;
}
