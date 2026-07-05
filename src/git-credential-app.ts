/**
 * git credential helper — mints a short-lived (~1h) GitHub App installation token so the build
 * host can fetch (READ-ONLY) from GitHub over HTTPS, for public AND private repos. Wired via
 * `git config --system credential.https://github.com.helper` in the Dockerfile; it caches nothing.
 *
 * Config comes from the container env (set by the quadlet):
 *   GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, GITHUB_APP_KEY_FILE (path to the App private-key .pem)
 *
 * On `get` for github.com it signs an App JWT (RS256) with the key, exchanges it for an
 * installation access token, and prints `username=x-access-token` + `password=<token>`.
 * `store`/`erase` are no-ops. On ANY error it prints no credential and exits 0 — git then surfaces
 * a normal auth failure — so the key and the token never reach git's error path (only a reason on
 * stderr). The token itself is written ONLY to stdout, which git consumes directly.
 */
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  base64UrlEncode,
  buildAppJwtSigningInput,
  parseGitCredentialRequest,
} from "./validation.js";

async function main(): Promise<void> {
  if (process.argv[2] !== "get") return; // store / erase: nothing to cache

  const req = parseGitCredentialRequest(readFileSync(0, "utf8"));
  if (req["host"] !== "github.com") return; // not ours — let git try other helpers

  const appId = process.env["GITHUB_APP_ID"];
  const installationId = process.env["GITHUB_APP_INSTALLATION_ID"];
  const keyFile = process.env["GITHUB_APP_KEY_FILE"];
  if (!appId || !installationId || !keyFile) {
    process.stderr.write(
      "git-credential-app: GITHUB_APP_ID / _INSTALLATION_ID / _KEY_FILE not set\n",
    );
    return;
  }

  // Sign an App JWT (RS256) with the private key.
  let jwt: string;
  try {
    const signingInput = buildAppJwtSigningInput(appId, Math.floor(Date.now() / 1000));
    const signer = createSign("RSA-SHA256");
    signer.update(signingInput);
    signer.end();
    jwt = `${signingInput}.${base64UrlEncode(signer.sign(readFileSync(keyFile)))}`;
  } catch (err) {
    process.stderr.write(
      `git-credential-app: could not sign JWT with ${keyFile}: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return;
  }

  // Exchange the JWT for an installation access token (scoped to the App's installed repos).
  let res: Response;
  try {
    res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "mcp-android-credential-helper",
      },
    });
  } catch (err) {
    process.stderr.write(
      `git-credential-app: installation-token request errored: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return;
  }
  if (!res.ok) {
    process.stderr.write(
      `git-credential-app: installation-token request failed (HTTP ${res.status})\n`,
    );
    return;
  }

  const body = (await res.json()) as { token?: string };
  if (!body.token) {
    process.stderr.write("git-credential-app: installation-token response had no token\n");
    return;
  }
  process.stdout.write(`username=x-access-token\npassword=${body.token}\n`);
}

// Fail-safe: ANY unexpected throw (e.g. a non-JSON 2xx body from res.json(), or a stdin read
// error) must still exit 0 with no credential printed, so git falls back to a normal auth failure
// rather than a helper crash. The message carries no secret (fs/JSON error text only).
main().catch((err: unknown) => {
  process.stderr.write(
    `git-credential-app: unexpected error: ${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exit(0);
});
