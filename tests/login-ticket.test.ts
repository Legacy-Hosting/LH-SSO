import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { config } from "../src/config.js";
import { closeDatabase, database } from "../src/database/mysql.js";
import {
  consumeLoginTicket,
  issueLoginTicket,
  provisionLegacyUser,
} from "../src/login-ticket.js";

after(async () => {
  await closeDatabase();
});

test("login tickets are account-bound, short-lived, and single-use", {
  skip: !config.DATABASE_URL,
}, async () => {
  const subject = randomUUID();
  const interactionUid = `interaction_${randomUUID().replaceAll("-", "")}`;
  try {
    await provisionLegacyUser({
      subject,
      email: `${subject}@example.com`,
      displayName: "OIDC ticket test",
    });
    await provisionLegacyUser({
      subject,
      email: `${subject}@example.com`,
      displayName: "Updated OIDC ticket test",
    });
    await assert.rejects(
      provisionLegacyUser({
        subject: randomUUID(),
        email: `${subject}@example.com`,
        displayName: "Conflicting identity",
      }),
      /identity_conflict/,
    );
    const mismatchedSubject = randomUUID();
    await database().execute(
      `INSERT INTO sso_identities (id,user_id,provider,provider_subject)
       SELECT UUID_TO_BIN(?),id,'legacy_panel',? FROM sso_users WHERE subject=?`,
      [randomUUID(), mismatchedSubject, subject],
    );
    await assert.rejects(
      provisionLegacyUser({
        subject: mismatchedSubject,
        email: `${mismatchedSubject}@example.com`,
        displayName: "Mismatched legacy identity",
      }),
      /identity_conflict/,
    );
    const issued = await issueLoginTicket(interactionUid, subject, "passkey");
    assert.ok(issued);
    assert.equal(issued.expiresIn, 60);
    assert.deepEqual(await consumeLoginTicket(issued.ticket, interactionUid), {
      subject,
      authenticationMethod: "passkey",
    });
    assert.equal(await consumeLoginTicket(issued.ticket, interactionUid), undefined);
  } finally {
    await database().execute("DELETE FROM sso_users WHERE subject=?", [subject]);
  }
});
