import type { PoolConnection, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { database } from "./database/mysql.js";

export const staffRoles = [
  "founder",
  "management",
  "platform_admin",
  "developer",
  "infrastructure",
  "support",
  "sales",
] as const;

export const discordRoleSyncBody = z.object({
  discordUserId: z.string().regex(/^\d{17,20}$/),
  discordGuildId: z.string().regex(/^\d{17,20}$/),
  staffRoles: z.array(z.enum(staffRoles)).max(staffRoles.length),
});

export type DiscordRoleSync = z.infer<typeof discordRoleSyncBody>;

export function normalizedStaffRoles(input: unknown) {
  return z.array(z.enum(staffRoles)).max(staffRoles.length).parse(input)
    .filter((role, index, roles) => roles.indexOf(role) === index);
}

export async function applyDiscordRoles(
  connection: PoolConnection,
  userId: string,
  roles: readonly (typeof staffRoles)[number][],
) {
  await connection.execute(
    "DELETE FROM sso_user_roles WHERE user_id=UUID_TO_BIN(?) AND source='discord'",
    [userId],
  );
  for (const role of normalizedStaffRoles(roles)) {
    await connection.execute(
      "INSERT INTO sso_user_roles (user_id,role_key,source) VALUES (UUID_TO_BIN(?),?,'discord')",
      [userId, role],
    );
  }
}

export async function syncDiscordRoles(sync: DiscordRoleSync) {
  const connection = await database().getConnection();
  try {
    await connection.beginTransaction();
    const roles = normalizedStaffRoles(sync.staffRoles);
    await connection.execute(
      `INSERT INTO discord_role_syncs (discord_user_id,discord_guild_id,staff_roles)
       VALUES (?,?,?) AS incoming
       ON DUPLICATE KEY UPDATE discord_guild_id=incoming.discord_guild_id,
         staff_roles=incoming.staff_roles,updated_at=CURRENT_TIMESTAMP(3)`,
      [sync.discordUserId, sync.discordGuildId, JSON.stringify(roles)],
    );
    const [identities] = await connection.query<(RowDataPacket & { userId: string })[]>(
      `SELECT BIN_TO_UUID(user_id) AS userId FROM sso_identities
       WHERE provider='discord' AND provider_subject=? LIMIT 1`,
      [sync.discordUserId],
    );
    const userId = identities[0]?.userId;
    if (userId) await applyDiscordRoles(connection, userId, roles);
    await connection.commit();
    return { linked: Boolean(userId), staffRoles: roles };
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}
