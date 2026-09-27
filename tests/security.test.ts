import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { discordRoleSyncBody } from "../src/discord-role-sync.js";
import { validInternalBearer } from "../src/internal-auth.js";

const token = "a".repeat(32);

test("internal authentication requires the exact bearer token", () => {
  assert.equal(validInternalBearer(`Bearer ${token}`, token), true);
  assert.equal(validInternalBearer(`Bearer ${"b".repeat(32)}`, token), false);
  assert.equal(validInternalBearer(undefined, token), false);
});

test("Discord can synchronize only recognized staff roles", () => {
  assert.equal(
    discordRoleSyncBody.safeParse({
      discordUserId: "12345678901234567",
      discordGuildId: "22345678901234567",
      staffRoles: ["developer", "support"],
    }).success,
    true,
  );
  assert.equal(
    discordRoleSyncBody.safeParse({
      discordUserId: "12345678901234567",
      discordGuildId: "22345678901234567",
      staffRoles: ["premium_customer"],
    }).success,
    false,
  );
});

test("Nginx sends OIDC authorization continuations to the protocol server", () => {
  const nginx = readFileSync("ops/nginx/auth.legacyhosting.xyz.conf", "utf8");
  assert.match(nginx, /auth\(\?:\/\|\$\)/);
  assert.match(
    nginx,
    /location ~ [^{]+auth\(\?:\/\|\$\)[^{]+\{[\s\S]*?proxy_pass http:\/\/127\.0\.0\.1:8081;/,
  );
});
