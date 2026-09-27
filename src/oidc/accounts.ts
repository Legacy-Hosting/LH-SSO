import type { Account, FindAccount } from "oidc-provider";
import type { RowDataPacket } from "mysql2";
import { database } from "../database/mysql.js";

type UserRow = RowDataPacket & {
  subject: string;
  displayName: string;
  email: string | null;
};

type RoleRow = RowDataPacket & { roleKey: string };

export async function accountClaims(subject: string) {
  const [users] = await database().query<UserRow[]>(
    `SELECT subject,display_name AS displayName,email
     FROM sso_users WHERE subject=? AND disabled_at IS NULL LIMIT 1`,
    [subject],
  );
  const user = users[0];
  if (!user) return undefined;
  const [roles] = await database().query<RoleRow[]>(
    `SELECT DISTINCT role_key AS roleKey FROM sso_user_roles
     WHERE user_id=(SELECT id FROM sso_users WHERE subject=? LIMIT 1)
     ORDER BY role_key`,
    [subject],
  );
  return {
    sub: user.subject,
    name: user.displayName,
    ...(user.email ? { email: user.email, email_verified: true } : {}),
    roles: roles.map((role) => role.roleKey),
  };
}

export const findSsoAccount: FindAccount = async (_context, subject): Promise<Account | undefined> => {
  const claims = await accountClaims(subject);
  if (!claims) return undefined;
  return {
    accountId: subject,
    async claims() {
      return claims;
    },
  };
};
