import formbody from "@fastify/formbody";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import type Provider from "oidc-provider";
import { z } from "zod";
import { databaseStatus } from "./database/mysql.js";
import { discordRoleSyncBody, syncDiscordRoles } from "./discord-role-sync.js";
import { validInternalBearer } from "./internal-auth.js";
import {
  consumeLoginTicket,
  issueLoginTicket,
  provisionLegacyUser,
} from "./login-ticket.js";

type AppOptions = {
  internalToken: string;
  identityBridgeToken?: string;
  oidcProvider?: Provider;
  oidcIssuer?: string;
  legacyLoginUrl?: string;
  trustProxy?: boolean;
  loginTickets?: {
    provision: typeof provisionLegacyUser;
    issue: typeof issueLoginTicket;
    consume: typeof consumeLoginTicket;
  };
};

const interactionParams = {
  type: "object",
  required: ["uid"],
  properties: { uid: { type: "string", minLength: 16, maxLength: 255, pattern: "^[A-Za-z0-9_-]+$" } },
} as const;

const loginTicketBody = z.object({
  interactionUid: z.string().regex(/^[A-Za-z0-9_-]{16,255}$/),
  subject: z.string().uuid(),
  email: z.string().trim().email().max(320),
  displayName: z.string().trim().min(2).max(120),
});

function stringArray(value: unknown) {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string")
    ? value
    : undefined;
}

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
  void app.register(formbody);
  void app.register(rateLimit, { max: 120, timeWindow: 60_000 });

  app.get("/", async () => ({
    service: "LH-SSO",
    version: "1.1.1",
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

  if (
    options.oidcProvider &&
    options.oidcIssuer &&
    options.legacyLoginUrl &&
    options.identityBridgeToken
  ) {
    const provider = options.oidcProvider;
    const tickets = options.loginTickets ?? {
      provision: provisionLegacyUser,
      issue: issueLoginTicket,
      consume: consumeLoginTicket,
    };

    app.post("/internal/oidc/login-tickets", async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      if (!validInternalBearer(request.headers.authorization, options.identityBridgeToken!)) {
        return reply.status(401).send({ error: "invalid_internal_token" });
      }
      const body = loginTicketBody.safeParse(request.body);
      if (!body.success) return reply.status(400).send({ error: "validation_error" });
      const { interactionUid, subject } = body.data;
      if (!await provider.Interaction.find(interactionUid)) {
        return reply.status(404).send({ error: "interaction_not_found" });
      }
      try {
        await tickets.provision({
          subject,
          email: body.data.email,
          displayName: body.data.displayName,
        });
      } catch (error) {
        if (error instanceof Error && error.message === "identity_conflict") {
          return reply.status(409).send({ error: "identity_conflict" });
        }
        throw error;
      }
      const issued = await tickets.issue(interactionUid, subject);
      if (!issued) return reply.status(404).send({ error: "account_not_found" });
      return reply.status(201).send({
        data: {
          ...issued,
          completionUri: `${options.oidcIssuer}/interaction/${interactionUid}/complete`,
        },
      });
    });

    app.get<{ Params: { uid: string } }>(
      "/interaction/:uid",
      { schema: { params: interactionParams } },
      async (request, reply) => {
        reply.header("Cache-Control", "no-store");
        const details = await provider.interactionDetails(request.raw, reply.raw);
        if (details.uid !== request.params.uid) {
          return reply.status(400).send({ error: "interaction_mismatch" });
        }
        if (details.prompt.name === "login") {
          const loginUrl = new URL(options.legacyLoginUrl!);
          loginUrl.searchParams.set("sso_interaction", details.uid);
          loginUrl.searchParams.set(
            "sso_completion_uri",
            `${options.oidcIssuer}/interaction/${details.uid}/complete`,
          );
          loginUrl.searchParams.set("sso_issuer", options.oidcIssuer!);
          return reply.redirect(loginUrl.toString());
        }
        if (details.prompt.name !== "consent" || !details.session?.accountId) {
          return reply.status(400).send({ error: "unsupported_interaction" });
        }

        let grant = details.grantId ? await provider.Grant.find(details.grantId) : undefined;
        grant ??= new provider.Grant({
          accountId: details.session.accountId,
          clientId: String(details.params.client_id),
        });
        const missingScopes = stringArray(details.prompt.details.missingOIDCScope);
        if (missingScopes) grant.addOIDCScope(missingScopes.join(" "));
        const missingClaims = stringArray(details.prompt.details.missingOIDCClaims);
        if (missingClaims) grant.addOIDCClaims(missingClaims);
        const missingResources = details.prompt.details.missingResourceScopes;
        if (missingResources && typeof missingResources === "object") {
          for (const [indicator, scopes] of Object.entries(missingResources)) {
            const values = stringArray(scopes);
            if (values) grant.addResourceScope(indicator, values.join(" "));
          }
        }
        const grantId = await grant.save();
        reply.hijack();
        await provider.interactionFinished(
          request.raw,
          reply.raw,
          { consent: { grantId } },
          { mergeWithLastSubmission: true },
        );
      },
    );

    app.post<{ Params: { uid: string } }>(
      "/interaction/:uid/complete",
      { schema: { params: interactionParams } },
      async (request, reply) => {
        reply.header("Cache-Control", "no-store");
        const details = await provider.interactionDetails(request.raw, reply.raw);
        if (details.uid !== request.params.uid || details.prompt.name !== "login") {
          return reply.status(400).send({ error: "interaction_mismatch" });
        }
        const body = request.body as Record<string, unknown> | null;
        const ticket = typeof body?.ticket === "string" ? body.ticket : "";
        if (!/^[A-Za-z0-9_-]{43}$/.test(ticket)) {
          return reply.status(400).send({ error: "invalid_login_ticket" });
        }
        const subject = await tickets.consume(ticket, request.params.uid);
        if (!subject) return reply.status(401).send({ error: "invalid_login_ticket" });
        reply.hijack();
        await provider.interactionFinished(request.raw, reply.raw, {
          login: {
            accountId: subject,
            acr: "urn:legacyhosting:identity:legacy-panel",
            amr: ["legacy_panel"],
            remember: true,
          },
        });
      },
    );
  }

  app.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error }, "SSO request failed");
    if (reply.raw.headersSent) {
      if (!reply.raw.writableEnded) reply.raw.end();
      return;
    }
    return reply.status(500).send({ error: "internal_server_error" });
  });

  return app;
}
