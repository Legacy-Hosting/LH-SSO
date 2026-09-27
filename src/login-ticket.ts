import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { RowDataPacket } from "mysql2";
import { database } from "./database/mysql.js";

const ticketLifetimeSeconds = 60;

function ticketHash(ticket: string) {
  return createHash("sha256").update(ticket, "utf8").digest();
}

export async function provisionLegacyUser(input: {
  subject: string;
  email: string;
  displayName: string;
}) {
  const connection = await database().getConnection();
  try {
    await connection.beginTransaction();
    const email = input.email.toLowerCase();
    const [matches] = await connection.query<(RowDataPacket & { subject: string; email: string })[]>(
      "SELECT subject,email FROM sso_users WHERE subject=? OR email=? FOR UPDATE",
      [input.subject, email],
    );
    if (matches.some((match) => match.email === email && match.subject !== input.subject)) {
      throw new Error("identity_conflict");
    }
    if (matches.some((match) => match.subject === input.subject)) {
      await connection.execute(
        "UPDATE sso_users SET display_name=?,email=? WHERE subject=?",
        [input.displayName, email, input.subject],
      );
    } else {
      await connection.execute(
        "INSERT INTO sso_users (id,subject,display_name,email) VALUES (UUID_TO_BIN(?),?,?,?)",
        [randomUUID(), input.subject, input.displayName, email],
      );
    }
    await connection.execute(
      `INSERT INTO sso_identities (id,user_id,provider,provider_subject)
       SELECT UUID_TO_BIN(?),id,'legacy_panel',subject FROM sso_users WHERE subject=?
       ON DUPLICATE KEY UPDATE updated_at=CURRENT_TIMESTAMP(3)`,
      [randomUUID(), input.subject],
    );
    const [linkedIdentities] = await connection.query<(RowDataPacket & { linked: number })[]>(
      `SELECT 1 AS linked
       FROM sso_identities i
       JOIN sso_users u ON u.id=i.user_id
       WHERE i.provider='legacy_panel' AND i.provider_subject=? AND u.subject=?
       LIMIT 1`,
      [input.subject, input.subject],
    );
    if (!linkedIdentities[0]) throw new Error("identity_conflict");
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ER_DUP_ENTRY"
    ) {
      throw new Error("identity_conflict", { cause: error });
    }
    throw error;
  } finally {
    connection.release();
  }
}

export async function issueLoginTicket(interactionUid: string, subject: string) {
  await database().execute(
    "DELETE FROM sso_login_tickets WHERE expires_at<=UTC_TIMESTAMP(3) OR consumed_at IS NOT NULL",
  );
  const [users] = await database().query<(RowDataPacket & { userId: Buffer })[]>(
    "SELECT id AS userId FROM sso_users WHERE subject=? AND disabled_at IS NULL LIMIT 1",
    [subject],
  );
  const user = users[0];
  if (!user) return undefined;

  const ticket = randomBytes(32).toString("base64url");
  await database().execute(
    `INSERT INTO sso_login_tickets
       (token_hash,interaction_uid,user_id,expires_at)
     VALUES (?,?,?,TIMESTAMPADD(SECOND,?,UTC_TIMESTAMP(3)))`,
    [ticketHash(ticket), interactionUid, user.userId, ticketLifetimeSeconds],
  );
  return { ticket, expiresIn: ticketLifetimeSeconds };
}

export async function consumeLoginTicket(ticket: string, interactionUid: string) {
  const connection = await database().getConnection();
  try {
    await connection.beginTransaction();
    const [rows] = await connection.query<(RowDataPacket & { subject: string })[]>(
      `SELECT u.subject
       FROM sso_login_tickets t
       JOIN sso_users u ON u.id=t.user_id
       WHERE t.token_hash=? AND t.interaction_uid=? AND t.consumed_at IS NULL
         AND t.expires_at>UTC_TIMESTAMP(3) AND u.disabled_at IS NULL
       LIMIT 1 FOR UPDATE`,
      [ticketHash(ticket), interactionUid],
    );
    const subject = rows[0]?.subject;
    if (!subject) {
      await connection.rollback();
      return undefined;
    }
    await connection.execute(
      "UPDATE sso_login_tickets SET consumed_at=UTC_TIMESTAMP(3) WHERE token_hash=?",
      [ticketHash(ticket)],
    );
    await connection.commit();
    return subject;
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}
