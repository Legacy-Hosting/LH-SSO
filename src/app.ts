import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { databaseStatus } from "./database/mysql.js";
import { discordRoleSyncBody, syncDiscordRoles } from "./discord-role-sync.js";
import { validInternalBearer } from "./internal-auth.js";

type AppOptions = {
  internalToken: string;
  trustProxy?: boolean;
};

export function createApp(options: AppOptions) {
  const app = Fastify({
    trustProxy: options.trustProxy ?? false,
    bodyLimit: 128 * 1024,
    logger: true,
    requestIdHeader: "x-request-id",
  });

  void app.register(helmet, {
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  });
  void app.register(rateLimit, { max: 120, timeWindow: 60_000 });

  app.get("/", async () => ({
    service: "LH-SSO",
    version: "1.0.0",
    status: "operational",
  }));

  app.get("/health", async (_request, reply) => {
    const database = await databaseStatus();
    const healthy = database === "connected";
    return reply.status(healthy ? 200 : 503).send({
      status: healthy ? "ok" : "degraded",
      database,
    });
  });

  app.post("/internal/discord/role-sync", async (request, reply) => {
    if (!validInternalBearer(request.headers.authorization, options.internalToken)) {
      return reply.status(401).send({ error: "invalid_internal_token" });
    }
    const body = discordRoleSyncBody.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: "validation_error" });
    }
    const result = await syncDiscordRoles(body.data);
    return reply.status(202).send({ data: result });
  });

  app.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error }, "SSO request failed");
    return reply.status(500).send({ error: "internal_server_error" });
  });

  return app;
}
