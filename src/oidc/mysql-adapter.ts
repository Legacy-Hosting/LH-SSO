import type { Adapter, AdapterPayload } from "oidc-provider";
import type { RowDataPacket } from "mysql2";
import { database } from "../database/mysql.js";

type ArtifactRow = RowDataPacket & { payload: AdapterPayload | string };
let nextCleanupAt = 0;

function decodedPayload(value: AdapterPayload | string) {
  return typeof value === "string" ? (JSON.parse(value) as AdapterPayload) : value;
}

export class MySqlOidcAdapter implements Adapter {
  readonly #model: string;

  constructor(model: string) {
    this.#model = model;
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number) {
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1_000) : null;
    await database().execute(
      `INSERT INTO sso_oidc_artifacts
         (model,artifact_id,payload,grant_id,user_code,uid,expires_at)
       VALUES (?,?,?,?,?,?,?) AS incoming
       ON DUPLICATE KEY UPDATE payload=incoming.payload,grant_id=incoming.grant_id,
         user_code=incoming.user_code,uid=incoming.uid,expires_at=incoming.expires_at`,
      [
        this.#model,
        id,
        JSON.stringify(payload),
        payload.grantId ?? null,
        payload.userCode ?? null,
        payload.uid ?? null,
        expiresAt,
      ],
    );
    if (Date.now() >= nextCleanupAt) {
      nextCleanupAt = Date.now() + 60_000;
      await database().execute(
        "DELETE FROM sso_oidc_artifacts WHERE expires_at<=UTC_TIMESTAMP(3) LIMIT 1000",
      );
    }
  }

  async find(id: string) {
    return this.#findBy("artifact_id", id);
  }

  async findByUserCode(userCode: string) {
    return this.#findBy("user_code", userCode);
  }

  async findByUid(uid: string) {
    return this.#findBy("uid", uid);
  }

  async consume(id: string) {
    await database().execute(
      `UPDATE sso_oidc_artifacts
       SET payload=JSON_SET(payload,'$.consumed',CAST(? AS UNSIGNED))
       WHERE model=? AND artifact_id=? AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP(3))`,
      [Math.floor(Date.now() / 1_000), this.#model, id],
    );
  }

  async destroy(id: string) {
    await database().execute(
      "DELETE FROM sso_oidc_artifacts WHERE model=? AND artifact_id=?",
      [this.#model, id],
    );
  }

  async revokeByGrantId(grantId: string) {
    await database().execute(
      "DELETE FROM sso_oidc_artifacts WHERE model=? AND grant_id=?",
      [this.#model, grantId],
    );
  }

  async #findBy(column: "artifact_id" | "user_code" | "uid", value: string) {
    const [rows] = await database().query<ArtifactRow[]>(
      `SELECT payload FROM sso_oidc_artifacts
       WHERE model=? AND ${column}=? AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP(3))
       LIMIT 1`,
      [this.#model, value],
    );
    return rows[0] ? decodedPayload(rows[0].payload) : undefined;
  }
}
