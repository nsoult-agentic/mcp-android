/**
 * Mint a short-lived (~1h) GitHub App installation token for READ access to the App's installed
 * repos over the REST API. Shared by the git credential helper (HTTPS fetch of private sources) and
 * android-fetch-release (downloading a signed release asset into /data/builds).
 *
 * Config comes from the container env (set by the quadlet): GITHUB_APP_ID,
 * GITHUB_APP_INSTALLATION_ID, GITHUB_APP_KEY_FILE (path to the App private-key .pem).
 *
 * Signs an App JWT (RS256) with the key and exchanges it for an installation access token. Throws an
 * Error with a NON-secret message on any failure — the key and the token itself are never included
 * in a thrown message, so they can't reach a caller's error/log path.
 */
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";

import { base64UrlEncode, buildAppJwtSigningInput } from "./validation.js";

export async function mintInstallationToken(): Promise<string> {
  const appId = process.env["GITHUB_APP_ID"];
  const installationId = process.env["GITHUB_APP_INSTALLATION_ID"];
  const keyFile = process.env["GITHUB_APP_KEY_FILE"];
  if (!appId || !installationId || !keyFile) {
    throw new Error("GITHUB_APP_ID / _INSTALLATION_ID / _KEY_FILE not set");
  }

  // Sign an App JWT (RS256) with the private key.
  const signingInput = buildAppJwtSigningInput(appId, Math.floor(Date.now() / 1000));
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  const jwt = `${signingInput}.${base64UrlEncode(signer.sign(readFileSync(keyFile)))}`;

  // Exchange the JWT for an installation access token (scoped to the App's installed repos).
  const res = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "mcp-android",
      },
    },
  );
  if (!res.ok) throw new Error(`installation-token request failed (HTTP ${res.status})`);

  const body = (await res.json()) as { token?: string };
  if (!body.token) throw new Error("installation-token response had no token");
  return body.token;
}
