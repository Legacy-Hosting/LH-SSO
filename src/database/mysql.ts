import mysql, { type Pool } from "mysql2/promise";
import { config } from "../config.js";
import { databaseConnectionOptions } from "./connection-options.js";

let pool: Pool | undefined;
let statusCheck: Promise<"connected" | "unavailable"> | undefined;

function discardPool(candidate: Pool) {
  if (pool !== candidate) return;
  pool = undefined;
  void candidate.end().catch(() => undefined);
}

async function probe(candidate: Pool) {
  let timeout: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      candidate.query("SELECT 1"),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new Error("Database health check timed out")),
          config.DATABASE_HEALTH_TIMEOUT_MS,
        );
        timeout.unref();
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

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
  statusCheck ??= (async () => {
    const candidate = database();
    try {
      await probe(candidate);
      return "connected" as const;
    } catch {
      discardPool(candidate);
      return "unavailable" as const;
    }
  })().finally(() => {
    statusCheck = undefined;
  });
  return statusCheck;
}

export async function closeDatabase() {
  const previous = pool;
  pool = undefined;
  statusCheck = undefined;
  await previous?.end();
}
