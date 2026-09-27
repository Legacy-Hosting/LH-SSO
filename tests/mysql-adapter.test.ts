import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { config } from "../src/config.js";
import { closeDatabase } from "../src/database/mysql.js";
import { MySqlOidcAdapter } from "../src/oidc/mysql-adapter.js";

after(async () => {
  await closeDatabase();
});

test("the MySQL adapter persists, consumes, looks up, and revokes OIDC artifacts", {
  skip: !config.DATABASE_URL,
}, async () => {
  const model = `Test-${randomUUID()}`;
  const adapter = new MySqlOidcAdapter(model);
  const firstId = randomUUID();
  const secondId = randomUUID();
  const grantId = randomUUID();
  const uid = randomUUID();
  const userCode = randomUUID();

  await adapter.upsert(firstId, { grantId, uid, userCode, scope: "openid roles" }, 60);
  assert.equal((await adapter.find(firstId))?.scope, "openid roles");
  assert.equal((await adapter.findByUid(uid))?.grantId, grantId);
  assert.equal((await adapter.findByUserCode(userCode))?.grantId, grantId);

  await adapter.consume(firstId);
  assert.equal(typeof (await adapter.find(firstId))?.consumed, "number");

  await adapter.upsert(secondId, { grantId }, 60);
  await adapter.revokeByGrantId(grantId);
  assert.equal(await adapter.find(firstId), undefined);
  assert.equal(await adapter.find(secondId), undefined);
});
