import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import { config } from "../src/config.js";
import { closeDatabase, database } from "../src/database/mysql.js";
import { consumeLoginTicket, issueLoginTicket } from "../src/login-ticket.js";

after(async () => {
  await closeDatabase();
});

test("login tickets are account-bound, short-lived, and single-use", {
  skip: !config.DATABASE_URL,
}, async () => {
  const subject = randomUUID();
  const interactionUid = `interaction_${randomUUID().replaceAll("-", "")}`;
  await database().execute(
    "INSERT INTO sso_users (id,subject,display_name) VALUES (UUID_TO_BIN(?),?,?)",
    [randomUUID(), subject, "OIDC ticket test"],
  );
  try {
    const issued = await issueLoginTicket(interactionUid, subject);
    assert.ok(issued);
    assert.equal(issued.expiresIn, 60);
    assert.equal(await consumeLoginTicket(issued.ticket, interactionUid), subject);
    assert.equal(await consumeLoginTicket(issued.ticket, interactionUid), undefined);
  } finally {
    await database().execute("DELETE FROM sso_users WHERE subject=?", [subject]);
  }
});
