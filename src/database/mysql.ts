import mysql, { type Pool } from "mysql2/promise";
import { config } from "../config.js";
import { databaseConnectionOptions } from "./connection-options.js";

let pool: Pool | undefined;

export function database() {
  if (!config.DATABASE_URL) throw new Error("DATABASE_URL is not configured");
  pool ??= mysql.createPool({
    ...databaseConnectionOptions(),
    connectionLimit: 5,
    maxIdle: 2,
    idleTimeout: 60_000,
    queueLimit: 50,
    connectTimeout: config.DATABASE_CONNECT_TIMEOUT_MS,
    enableKeepAlive: true,
  });
  return pool;
}

export async function databaseStatus() {
  if (!config.DATABASE_URL) return "not_configured" as const;
  try {
    await database().query("SELECT 1");
    return "connected" as const;
  } catch {
    const previous = pool;
    pool = undefined;
    await previous?.end().catch(() => undefined);
    return "unavailable" as const;
  }
}

export async function closeDatabase() {
  const previous = pool;
  pool = undefined;
  await previous?.end();
}
