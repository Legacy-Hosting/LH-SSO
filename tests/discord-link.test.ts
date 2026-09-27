import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { after, test } from "node:test";
import type { RowDataPacket } from "mysql2";
import { config } from "../src/config.js";
import { closeDatabase, database } from "../src/database/mysql.js";
import {
  completeDiscordLink,
  inspectDiscordLinkTicket,
  issueDiscordLinkTicket,
} from "../src/discord-link.js";

after(async () => {
  await closeDatabase();
});

test("Discord links are hashed, account-bound, role-aware, and single-use", {
  skip: !config.DATABASE_URL,
}, async () => {
  const userId = randomUUID();
  const subject = randomUUID();
  const discordUserId = "92345678901234567";
  const discordGuildId = "82345678901234567";
  try {
    await database().execute(
      "DELETE FROM discord_link_tickets WHERE discord_user_id=?",
      [discordUserId],
    );
    await database().execute(
      "DELETE FROM discord_role_syncs WHERE discord_user_id=?",
      [discordUserId],
    );
    await database().execute(
      `INSERT INTO sso_users (id,subject,display_name,email)
       VALUES (UUID_TO_BIN(?),?,'Discord Link User',?)`,
      [userId, subject, `${subject}@example.com`],
    );
    await database().execute(
      `INSERT INTO discord_role_syncs (discord_user_id,discord_guild_id,staff_roles)
       VALUES (?,?,?)`,
      [discordUserId, discordGuildId, JSON.stringify(["developer", "support"])],
    );

    const issued = await issueDiscordLinkTicket({ discordUserId, discordGuildId });
    assert.equal(issued.ticket.length, 43);
    assert.equal(issued.expiresIn, 600);
    const inspected = await inspectDiscordLinkTicket(issued.ticket);
    assert.equal(inspected?.discordUserId, discordUserId);

    const [stored] = await database().query<(RowDataPacket & { hash: string })[]>(
      `SELECT HEX(token_hash) AS hash FROM discord_link_tickets
       WHERE discord_user_id=? ORDER BY created_at DESC LIMIT 1`,
      [discordUserId],
    );
    assert.equal(stored[0]?.hash.length, 64);
    assert.notEqual(stored[0]?.hash, issued.ticket);

    assert.deepEqual(await completeDiscordLink(issued.ticket, subject), {
      discordUserId,
      staffRoles: ["developer", "support"],
    });
    assert.equal(await inspectDiscordLinkTicket(issued.ticket), undefined);
    await assert.rejects(
      completeDiscordLink(issued.ticket, subject),
      /invalid_or_expired_discord_link/,
    );

    const [identities] = await database().query<(RowDataPacket & { subject: string })[]>(
      `SELECT provider_subject AS subject FROM sso_identities
       WHERE user_id=UUID_TO_BIN(?) AND provider='discord'`,
      [userId],
    );
    assert.deepEqual(identities.map((identity) => identity.subject), [discordUserId]);
    const [roles] = await database().query<(RowDataPacket & { role: string })[]>(
      `SELECT role_key AS role FROM sso_user_roles
       WHERE user_id=UUID_TO_BIN(?) AND source='discord' ORDER BY role_key`,
      [userId],
    );
    assert.deepEqual(roles.map((role) => role.role), ["developer", "support"]);
  } finally {
    await database().execute("DELETE FROM discord_link_tickets WHERE discord_user_id=?", [discordUserId]);
    await database().execute("DELETE FROM sso_users WHERE id=UUID_TO_BIN(?)", [userId]);
    await database().execute("DELETE FROM discord_role_syncs WHERE discord_user_id=?", [discordUserId]);
  }
});
