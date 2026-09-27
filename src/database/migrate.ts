import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { RowDataPacket } from "mysql2";
import mysql from "mysql2/promise";
import { config } from "../config.js";
import { databaseConnectionOptions } from "./connection-options.js";

const lockName = "legacy-hosting-sso-schema-migrations";

async function migrate() {
  if (!config.DATABASE_URL) throw new Error("DATABASE_URL is not configured");
  const connection = await mysql.createConnection({
    ...databaseConnectionOptions(),
    multipleStatements: true,
  });
  try {
    const [[lock]] = await connection.query<(RowDataPacket & { acquired: number })[]>(
      "SELECT GET_LOCK(?, 30) AS acquired",
      [lockName],
    );
    if (!lock?.acquired) throw new Error("Could not acquire the SSO migration lock");
    await connection.query(`
      CREATE TABLE IF NOT EXISTS sso_schema_migrations (
        migration VARCHAR(255) PRIMARY KEY,
        checksum CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
        applied_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    `);
    const directory = resolve(process.cwd(), "database", "migrations");
    const migrations = (await readdir(directory))
      .filter((file) => file.endsWith(".sql"))
      .sort((left, right) => left.localeCompare(right));
    for (const migration of migrations) {
      const sql = await readFile(resolve(directory, migration), "utf8");
      const checksum = createHash("sha256").update(sql).digest("hex");
      const [rows] = await connection.query<(RowDataPacket & { checksum: string })[]>(
        "SELECT checksum FROM sso_schema_migrations WHERE migration=? LIMIT 1",
        [migration],
      );
      if (rows[0]) {
        if (rows[0].checksum !== checksum)
          throw new Error(`Applied migration ${migration} has changed on disk`);
        continue;
      }
      await connection.query(sql);
      await connection.execute(
        "INSERT INTO sso_schema_migrations (migration,checksum) VALUES (?,?)",
        [migration, checksum],
      );
      console.log(`Applied: ${migration}`);
    }
  } finally {
    try {
      await connection.query("SELECT RELEASE_LOCK(?)", [lockName]);
    } finally {
      await connection.end();
    }
  }
}

migrate().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
