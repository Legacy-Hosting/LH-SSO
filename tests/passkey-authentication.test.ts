import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { config } from "../src/config.js";
import { closeDatabase, database } from "../src/database/mysql.js";
import { beginPasskeyAuthentication } from "../src/passkey-authentication.js";

after(async () => {
  await closeDatabase();
});

test("SSO creates account-bound and discoverable passkey challenges", {
  skip: !config.DATABASE_URL,
}, async () => {
  const userId = randomUUID();
  const subject = randomUUID();
  const credentialId = `credential-${randomUUID()}`;
  try {
    await database().execute(
      `INSERT INTO sso_users (id,subject,display_name,email)
       VALUES (UUID_TO_BIN(?),?,'Passkey User','passkey@example.com')`,
      [userId, subject],
    );
    await database().execute(
      `INSERT INTO sso_passkeys
         (id,user_id,webauthn_user_id,credential_id,public_key,transports,source)
       VALUES (UUID_TO_BIN(?),UUID_TO_BIN(?),UUID_TO_BIN(?),?,X'01',?,'legacy_panel')`,
      [randomUUID(), userId, subject, credentialId, JSON.stringify(["internal"])],
    );

    const bound = await beginPasskeyAuthentication(
      "interaction_uid_123456",
      "PASSKEY@example.com",
    );
    assert.equal(bound.options.rpId, config.WEBAUTHN_RP_ID);
    assert.deepEqual(bound.options.allowCredentials, [{
      id: credentialId,
      transports: ["internal"],
      type: "public-key",
    }]);

    const discoverable = await beginPasskeyAuthentication("interaction_uid_654321");
    assert.deepEqual(discoverable.options.allowCredentials, []);
    await assert.rejects(
      beginPasskeyAuthentication("interaction_uid_missing", "missing@example.com"),
      /account_not_found/,
    );
  } finally {
    await database().execute("DELETE FROM sso_users WHERE id=UUID_TO_BIN(?)", [userId]);
  }
});
