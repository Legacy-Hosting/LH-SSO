import { createApp } from "./app.js";
import { config } from "./config.js";
import { closeDatabase } from "./database/mysql.js";
import { createOidcProvider } from "./oidc/provider.js";
import { loadOidcRuntimeConfig } from "./oidc/runtime-config.js";

if (!config.LH_DISCORD_INTERNAL_TOKEN || !config.LH_IDENTITY_BRIDGE_TOKEN) {
  throw new Error("LH_DISCORD_INTERNAL_TOKEN and LH_IDENTITY_BRIDGE_TOKEN are required to start LH-SSO");
}

const oidcRuntime = loadOidcRuntimeConfig();
const oidcProvider = createOidcProvider(oidcRuntime);

const app = createApp({
  internalToken: config.LH_DISCORD_INTERNAL_TOKEN,
  identityBridgeToken: config.LH_IDENTITY_BRIDGE_TOKEN,
  oidcProvider,
  oidcIssuer: oidcRuntime.issuer,
  legacyLoginUrl: oidcRuntime.legacyLoginUrl,
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
