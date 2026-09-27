import { createOidcProvider } from "./oidc/provider.js";
import { loadOidcRuntimeConfig } from "./oidc/runtime-config.js";
import { closeDatabase } from "./database/mysql.js";

const runtime = loadOidcRuntimeConfig();
const provider = createOidcProvider(runtime);
const server = provider.listen(runtime.port, "127.0.0.1", () => {
  console.log(`LH-SSO OIDC provider listening on 127.0.0.1:${runtime.port}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    server.close(async (error) => {
      await closeDatabase();
      process.exit(error ? 1 : 0);
    });
  });
}
