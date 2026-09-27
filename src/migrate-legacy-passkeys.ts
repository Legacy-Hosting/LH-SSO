import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import mysql, { type ConnectionOptions, type RowDataPacket } from "mysql2/promise";
import { config } from "./config.js";

type LegacyPasskey = RowDataPacket & {
  subject: string;
  email: string;
  displayName: string;
  webauthnUserId: Buffer;
  credentialId: string;
  publicKey: Buffer;
  counter: number;
  deviceType: "singleDevice" | "multiDevice" | null;
  backedUp: number;
  transports: string | null;
  deviceName: string | null;
  createdAt: Date;
  lastUsedAt: Date | null;
};

function required(value: string | undefined, name: string) {
  if (!value) throw new Error(`${name} is required for passkey migration`);
  return value;
}

function connectionOptions(databaseUrl: string, caFile?: string): ConnectionOptions {
  const url = new URL(databaseUrl);
  for (const key of [...url.searchParams.keys()]) {
    if (key.toLowerCase() === "ssl-mode") url.searchParams.delete(key);
  }
  return {
    uri: url.toString(),
    timezone: "Z",
    connectTimeout: config.DATABASE_CONNECT_TIMEOUT_MS,
    ...(caFile
      ? {
          ssl: {
            ca: readFileSync(caFile, "utf8"),
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
          },
        }
      : {}),
  };
}

async function migrate() {
  const apply = process.argv.includes("--apply");
  const sourceUrl = required(config.LEGACY_DATABASE_URL, "LEGACY_DATABASE_URL");
  const targetUrl = required(config.DATABASE_URL, "DATABASE_URL");
  const legacyRpId = required(config.LEGACY_WEBAUTHN_RP_ID, "LEGACY_WEBAUTHN_RP_ID");
  if (legacyRpId !== config.WEBAUTHN_RP_ID) {
    throw new Error("LEGACY_WEBAUTHN_RP_ID must exactly match WEBAUTHN_RP_ID");
  }
  const sourceIdentity = new URL(sourceUrl);
  const targetIdentity = new URL(targetUrl);
  if (
    sourceIdentity.host === targetIdentity.host &&
    sourceIdentity.pathname === targetIdentity.pathname
  ) {
    throw new Error("Legacy and SSO databases must differ");
  }

  const source = await mysql.createConnection(connectionOptions(
    sourceUrl,
    config.LEGACY_DATABASE_SSL_CA,
  ));
  const target = await mysql.createConnection(connectionOptions(
    targetUrl,
    config.DATABASE_SSL_CA,
  ));
  let migratedUsers = 0;
  let migratedPasskeys = 0;
  try {
    const [passkeys] = await source.query<LegacyPasskey[]>(
      `SELECT BIN_TO_UUID(u.id) AS subject,u.email,u.display_name AS displayName,
              p.webauthn_user_id AS webauthnUserId,p.credential_id AS credentialId,
              p.public_key AS publicKey,p.counter,p.device_type AS deviceType,
              p.backed_up AS backedUp,p.transports,p.device_name AS deviceName,
              p.created_at AS createdAt,p.last_used_at AS lastUsedAt
       FROM users u JOIN user_passkeys p ON p.user_id=u.id
       WHERE u.status='active'
       ORDER BY u.id,p.created_at`,
    );
    await target.beginTransaction();
    const seenUsers = new Set<string>();
    for (const passkey of passkeys) {
      const email = passkey.email.trim().toLowerCase();
      const [userMatches] = await target.query<(
        RowDataPacket & { id: string; subject: string; email: string | null }
      )[]>(
        `SELECT BIN_TO_UUID(id) AS id,subject,email FROM sso_users
         WHERE subject=? OR email=? FOR UPDATE`,
        [passkey.subject, email],
      );
      if (userMatches.some((user) => user.email === email && user.subject !== passkey.subject)) {
        throw new Error(`Identity collision for ${email}`);
      }
      let userId = userMatches.find((candidate) => candidate.subject === passkey.subject)?.id;
      if (!userId) {
        userId = randomUUID();
        await target.execute(
          `INSERT INTO sso_users (id,subject,display_name,email)
           VALUES (UUID_TO_BIN(?),?,?,?)`,
          [userId, passkey.subject, passkey.displayName, email],
        );
      } else {
        await target.execute(
          "UPDATE sso_users SET display_name=?,email=? WHERE id=UUID_TO_BIN(?)",
          [passkey.displayName, email, userId],
        );
      }
      if (!seenUsers.has(passkey.subject)) {
        await target.execute(
          `INSERT INTO sso_identities (id,user_id,provider,provider_subject)
           VALUES (UUID_TO_BIN(?),UUID_TO_BIN(?),'legacy_panel',?)
           ON DUPLICATE KEY UPDATE updated_at=CURRENT_TIMESTAMP(3)`,
          [randomUUID(), userId, passkey.subject],
        );
        const [identity] = await target.query<RowDataPacket[]>(
          `SELECT 1 FROM sso_identities
           WHERE user_id=UUID_TO_BIN(?) AND provider='legacy_panel' AND provider_subject=?`,
          [userId, passkey.subject],
        );
        if (!identity[0]) throw new Error(`Identity binding collision for ${passkey.subject}`);
        seenUsers.add(passkey.subject);
        migratedUsers += 1;
      }

      const [credentialMatches] = await target.query<(
        RowDataPacket & { userId: string; publicKey: Buffer }
      )[]>(
        `SELECT BIN_TO_UUID(user_id) AS userId,public_key AS publicKey
         FROM sso_passkeys WHERE credential_id=? FOR UPDATE`,
        [passkey.credentialId],
      );
      const credential = credentialMatches[0];
      if (credential && (
        credential.userId !== userId ||
        !credential.publicKey.equals(passkey.publicKey)
      )) {
        throw new Error(`Credential collision for ${passkey.credentialId.slice(0, 12)}`);
      }
      if (credential) {
        await target.execute(
          `UPDATE sso_passkeys
           SET counter=GREATEST(counter,?),device_type=?,backed_up=?,transports=?,
               device_name=?,last_used_at=?
           WHERE credential_id=? AND user_id=UUID_TO_BIN(?)`,
          [
            passkey.counter,
            passkey.deviceType,
            Boolean(passkey.backedUp),
            passkey.transports,
            passkey.deviceName,
            passkey.lastUsedAt,
            passkey.credentialId,
            userId,
          ],
        );
      } else {
        await target.execute(
          `INSERT INTO sso_passkeys
             (id,user_id,webauthn_user_id,credential_id,public_key,counter,
              device_type,backed_up,transports,device_name,source,created_at,last_used_at)
           VALUES (UUID_TO_BIN(?),UUID_TO_BIN(?),?,?,?,?,?,?,?,?,
                   'legacy_panel',?,?)`,
          [
            randomUUID(),
            userId,
            passkey.webauthnUserId,
            passkey.credentialId,
            passkey.publicKey,
            passkey.counter,
            passkey.deviceType,
            Boolean(passkey.backedUp),
            passkey.transports,
            passkey.deviceName,
            passkey.createdAt,
            passkey.lastUsedAt,
          ],
        );
      }
      migratedPasskeys += 1;
    }

    if (apply) await target.commit();
    else await target.rollback();
    console.log(JSON.stringify({
      mode: apply ? "applied" : "dry-run",
      users: migratedUsers,
      passkeys: migratedPasskeys,
      rpId: config.WEBAUTHN_RP_ID,
    }));
  } catch (error) {
    await target.rollback();
    throw error;
  } finally {
    await Promise.all([source.end(), target.end()]);
  }
}

migrate().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
