import { randomUUID } from "node:crypto";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
} from "@simplewebauthn/server";
import type { ResultSetHeader, RowDataPacket } from "mysql2";
import { config } from "./config.js";
import { database } from "./database/mysql.js";

type UserRow = RowDataPacket & { id: string };
type ChallengeRow = RowDataPacket & {
  id: string;
  userId: string | null;
  challenge: string;
};
type PasskeyRow = RowDataPacket & {
  userId: string;
  subject: string;
  credentialId: string;
  publicKey: Buffer;
  counter: number;
  transports: string | AuthenticatorTransport[] | null;
};

function parsedTransports(value: PasskeyRow["transports"]) {
  if (Array.isArray(value)) return value;
  if (typeof value !== "string") return undefined;
  try {
    return JSON.parse(value) as AuthenticatorTransport[];
  } catch {
    return undefined;
  }
}

export async function beginPasskeyAuthentication(
  interactionUid: string,
  email?: string,
) {
  let userId: string | null = null;
  let allowCredentials: { id: string; transports?: AuthenticatorTransport[] }[] = [];
  if (email) {
    const [users] = await database().query<UserRow[]>(
      `SELECT BIN_TO_UUID(id) AS id FROM sso_users
       WHERE email=? AND disabled_at IS NULL LIMIT 1`,
      [email.trim().toLowerCase()],
    );
    userId = users[0]?.id ?? null;
    if (!userId) throw new Error("account_not_found");
    const [passkeys] = await database().query<PasskeyRow[]>(
      `SELECT credential_id AS credentialId,transports
       FROM sso_passkeys WHERE user_id=UUID_TO_BIN(?)`,
      [userId],
    );
    if (!passkeys.length) throw new Error("passkey_not_registered");
    allowCredentials = passkeys.map((passkey) => {
      const transports = parsedTransports(passkey.transports);
      return {
        id: passkey.credentialId,
        ...(transports ? { transports } : {}),
      };
    });
  }

  const options = await generateAuthenticationOptions({
    rpID: config.WEBAUTHN_RP_ID,
    userVerification: "required",
    allowCredentials,
  });
  const challengeId = randomUUID();
  await database().execute(
    `DELETE FROM sso_auth_challenges
     WHERE expires_at<=UTC_TIMESTAMP(3)
        OR consumed_at<UTC_TIMESTAMP(3)-INTERVAL 1 HOUR`,
  );
  await database().execute(
    `INSERT INTO sso_auth_challenges
       (id,interaction_uid,user_id,challenge,expires_at)
     VALUES (UUID_TO_BIN(?),?,UUID_TO_BIN(?),?,TIMESTAMPADD(MINUTE,5,UTC_TIMESTAMP(3)))`,
    [challengeId, interactionUid, userId, options.challenge],
  );
  return { challengeId, options };
}

export async function finishPasskeyAuthentication(input: {
  interactionUid: string;
  challengeId: string;
  response: AuthenticationResponseJSON;
}) {
  const [challenges] = await database().query<ChallengeRow[]>(
    `SELECT BIN_TO_UUID(id) AS id,BIN_TO_UUID(user_id) AS userId,challenge
     FROM sso_auth_challenges
     WHERE id=UUID_TO_BIN(?) AND interaction_uid=? AND consumed_at IS NULL
       AND expires_at>UTC_TIMESTAMP(3)
     LIMIT 1`,
    [input.challengeId, input.interactionUid],
  );
  const challenge = challenges[0];
  if (!challenge) throw new Error("invalid_or_expired_challenge");

  const [passkeys] = await database().query<PasskeyRow[]>(
    `SELECT BIN_TO_UUID(p.user_id) AS userId,u.subject,
            p.credential_id AS credentialId,p.public_key AS publicKey,
            p.counter,p.transports
     FROM sso_passkeys p JOIN sso_users u ON u.id=p.user_id
     WHERE p.credential_id=? AND u.disabled_at IS NULL LIMIT 1`,
    [input.response.id],
  );
  const passkey = passkeys[0];
  if (!passkey || (challenge.userId && challenge.userId !== passkey.userId)) {
    throw new Error("unknown_passkey");
  }

  const credentialTransports = parsedTransports(passkey.transports);
  const verification = await verifyAuthenticationResponse({
    response: input.response,
    expectedChallenge: challenge.challenge,
    expectedOrigin: config.WEBAUTHN_ORIGIN,
    expectedRPID: config.WEBAUTHN_RP_ID,
    requireUserVerification: true,
    credential: {
      id: passkey.credentialId,
      publicKey: new Uint8Array(passkey.publicKey),
      counter: Number(passkey.counter),
      ...(credentialTransports ? { transports: credentialTransports } : {}),
    },
  });
  if (!verification.verified) throw new Error("passkey_verification_failed");

  const connection = await database().getConnection();
  try {
    await connection.beginTransaction();
    const [consumed] = await connection.execute<ResultSetHeader>(
      `UPDATE sso_auth_challenges SET consumed_at=UTC_TIMESTAMP(3)
       WHERE id=UUID_TO_BIN(?) AND interaction_uid=? AND consumed_at IS NULL
         AND expires_at>UTC_TIMESTAMP(3)`,
      [challenge.id, input.interactionUid],
    );
    if (!consumed.affectedRows) throw new Error("invalid_or_expired_challenge");
    const [updatedPasskey] = await connection.execute<ResultSetHeader>(
      `UPDATE sso_passkeys SET counter=?,last_used_at=UTC_TIMESTAMP(3)
       WHERE credential_id=? AND user_id=UUID_TO_BIN(?) AND counter=?`,
      [
        verification.authenticationInfo.newCounter,
        passkey.credentialId,
        passkey.userId,
        passkey.counter,
      ],
    );
    if (!updatedPasskey.affectedRows) throw new Error("passkey_counter_changed");
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
  return { subject: passkey.subject };
}
