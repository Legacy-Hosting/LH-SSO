import { readFileSync } from "node:fs";
import type { ConnectionOptions } from "mysql2";
import { config } from "../config.js";

function normalizedDatabaseUrl(databaseUrl: string) {
  const url = new URL(databaseUrl);
  for (const key of [...url.searchParams.keys()]) {
    if (key.toLowerCase() === "ssl-mode") url.searchParams.delete(key);
  }
  return url.toString();
}

export function databaseConnectionOptions(): ConnectionOptions {
  if (!config.DATABASE_URL) throw new Error("DATABASE_URL is not configured");
  const options: ConnectionOptions = {
    uri: normalizedDatabaseUrl(config.DATABASE_URL),
    timezone: "Z",
  };
  if (config.DATABASE_SSL_CA) {
    options.ssl = {
      ca: readFileSync(config.DATABASE_SSL_CA, "utf8"),
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
    };
  }
  return options;
}
