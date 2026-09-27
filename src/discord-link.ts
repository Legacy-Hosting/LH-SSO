import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { RowDataPacket } from "mysql2";
import { database } from "./database/mysql.js";
import { applyDiscordRoles, normalizedStaffRoles } from "./discord-role-sync.js";

type LinkTicketRow = RowDataPacket & {
  id: string;
  discordUserId: string;
  discordGuildId: string;
};

type IdentityRow = RowDataPacket & {
  userId: string;
  providerSubject: string;
};

type UserRow = RowDataPacket & { userId: string };
type RoleSyncRow = RowDataPacket & { staffRoles: unknown };

function tokenHash(token: string) {
  return createHash("sha256").update(token, "utf8").digest();
}

function parsedJson(value: unknown) {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return [];
  }
}

export function discordLinkInteractionUid(ticketId: string) {
  return `discord_link_${ticketId.replaceAll("-", "")}`;
}

export async function issueDiscordLinkTicket(input: {
  discordUserId: string;
  discordGuildId: string;
}) {
  const connection = await database().getConnection();
  try {
    await connection.beginTransaction();
    const [syncs] = await connection.query<RoleSyncRow[]>(
      `SELECT staff_roles AS staffRoles FROM discord_role_syncs
       WHERE discord_user_id=? AND discord_guild_id=? FOR UPDATE`,
      [input.discordUserId, input.discordGuildId],
    );
    const roles = normalizedStaffRoles(parsedJson(syncs[0]?.staffRoles ?? []));
    if (roles.length === 0) throw new Error("discord_staff_role_required");

    const ticket = randomBytes(32).toString("base64url");
    const id = randomUUID();
    await connection.execute(
      `UPDATE discord_link_tickets SET consumed_at=UTC_TIMESTAMP(3)
       WHERE discord_user_id=? AND consumed_at IS NULL`,
      [input.discordUserId],
    );
    await connection.execute(
      `INSERT INTO discord_link_tickets
         (id,discord_user_id,discord_guild_id,token_hash,expires_at)
       VALUES (UUID_TO_BIN(?),?,?,?,TIMESTAMPADD(MINUTE,10,UTC_TIMESTAMP(3)))`,
      [id, input.discordUserId, input.discordGuildId, tokenHash(ticket)],
    );
    await connection.commit();
    return { ticket, expiresIn: 600 };
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

export async function inspectDiscordLinkTicket(ticket: string) {
  const [tickets] = await database().query<LinkTicketRow[]>(
    `SELECT BIN_TO_UUID(id) AS id,discord_user_id AS discordUserId,
            discord_guild_id AS discordGuildId
     FROM discord_link_tickets
     WHERE token_hash=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3)
     LIMIT 1`,
    [tokenHash(ticket)],
  );
  return tickets[0];
}

export async function completeDiscordLink(ticket: string, subject: string) {
  const connection = await database().getConnection();
  try {
    await connection.beginTransaction();
    const [tickets] = await connection.query<LinkTicketRow[]>(
      `SELECT BIN_TO_UUID(id) AS id,discord_user_id AS discordUserId,
              discord_guild_id AS discordGuildId
       FROM discord_link_tickets
       WHERE token_hash=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3)
       LIMIT 1 FOR UPDATE`,
      [tokenHash(ticket)],
    );
    const link = tickets[0];
    if (!link) throw new Error("invalid_or_expired_discord_link");

    const [users] = await connection.query<UserRow[]>(
      `SELECT BIN_TO_UUID(id) AS userId FROM sso_users
       WHERE subject=? AND disabled_at IS NULL LIMIT 1 FOR UPDATE`,
      [subject],
    );
    const userId = users[0]?.userId;
    if (!userId) throw new Error("account_not_found");

    const [subjectIdentities] = await connection.query<IdentityRow[]>(
      `SELECT BIN_TO_UUID(user_id) AS userId,provider_subject AS providerSubject
       FROM sso_identities WHERE provider='discord' AND provider_subject=? LIMIT 1`,
      [link.discordUserId],
    );
    if (subjectIdentities[0] && subjectIdentities[0].userId !== userId) {
      throw new Error("discord_identity_already_linked");
    }
    const [userIdentities] = await connection.query<IdentityRow[]>(
      `SELECT BIN_TO_UUID(user_id) AS userId,provider_subject AS providerSubject
       FROM sso_identities WHERE user_id=UUID_TO_BIN(?) AND provider='discord' LIMIT 1`,
      [userId],
    );
    if (userIdentities[0] && userIdentities[0].providerSubject !== link.discordUserId) {
      throw new Error("sso_account_already_linked");
    }
    if (!subjectIdentities[0] && !userIdentities[0]) {
      await connection.execute(
        `INSERT INTO sso_identities (id,user_id,provider,provider_subject)
         VALUES (UUID_TO_BIN(?),UUID_TO_BIN(?),'discord',?)`,
        [randomUUID(), userId, link.discordUserId],
      );
    }

    const [syncs] = await connection.query<RoleSyncRow[]>(
      `SELECT staff_roles AS staffRoles FROM discord_role_syncs
       WHERE discord_user_id=? AND discord_guild_id=? LIMIT 1 FOR UPDATE`,
      [link.discordUserId, link.discordGuildId],
    );
    const roles = normalizedStaffRoles(parsedJson(syncs[0]?.staffRoles ?? []));
    if (roles.length === 0) throw new Error("discord_staff_role_required");
    await applyDiscordRoles(connection, userId, roles);
    await connection.execute(
      `UPDATE discord_link_tickets
       SET consumed_at=UTC_TIMESTAMP(3),linked_user_id=UUID_TO_BIN(?)
       WHERE id=UUID_TO_BIN(?) AND consumed_at IS NULL`,
      [userId, link.id],
    );
    await connection.commit();
    return { discordUserId: link.discordUserId, staffRoles: roles };
  } catch (error) {
    await connection.rollback();
    if (
      typeof error === "object" && error !== null && "code" in error &&
      error.code === "ER_DUP_ENTRY"
    ) {
      throw new Error("discord_identity_already_linked");
    }
    throw error;
  } finally {
    connection.release();
  }
}
