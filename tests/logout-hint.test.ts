import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { verifyLogoutHint } from "../src/oidc/logout-hint.js";

const secret = "test-client-secret-that-is-at-least-32-bytes";
const now = 1_790_529_600_000;

function hint(overrides: Record<string, unknown> = {}) {
  const issuedAt = Math.floor(now / 1_000);
  const payload = Buffer.from(JSON.stringify({
    v: 1,
    aud: "https://auth.legacyhosting.xyz",
    clientId: "lh-panel",
    redirectUri: "https://panel.legacyhosting.xyz/",
    iat: issuedAt,
    exp: issuedAt + 60,
    nonce: "x".repeat(22),
    ...overrides,
  })).toString("base64url");
  const signature = createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

const expected = {
  audience: "https://auth.legacyhosting.xyz",
  clientId: "lh-panel",
  clientSecret: secret,
  redirectUri: "https://panel.legacyhosting.xyz/",
  now: () => now,
};

test("logout hints are short-lived and bound to the client and redirect", () => {
  assert.equal(verifyLogoutHint({ hint: hint(), ...expected }), true);
  assert.equal(verifyLogoutHint({ hint: `${hint()}x`, ...expected }), false);
  assert.equal(verifyLogoutHint({ hint: hint({ clientId: "lh-hub" }), ...expected }), false);
  assert.equal(verifyLogoutHint({ hint: hint({ exp: Math.floor(now / 1_000) - 1 }), ...expected }), false);
});
