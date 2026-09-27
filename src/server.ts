import { createApp } from "./app.js";
import { config } from "./config.js";
import { closeDatabase } from "./database/mysql.js";

if (!config.LH_DISCORD_INTERNAL_TOKEN) {
  throw new Error("LH_DISCORD_INTERNAL_TOKEN is required to start LH-SSO");
}

const app = createApp({
  internalToken: config.LH_DISCORD_INTERNAL_TOKEN,
  trustProxy: config.TRUST_PROXY,
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, async () => {
    await app.close();
    await closeDatabase();
    process.exit(0);
  });
}

await app.listen({ host: config.HOST, port: config.PORT });
