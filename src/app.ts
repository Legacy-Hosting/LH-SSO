import formbody from "@fastify/formbody";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import type Provider from "oidc-provider";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { z } from "zod";
import { databaseStatus } from "./database/mysql.js";
import {
  completeDiscordLink,
  discordLinkInteractionUid,
  inspectDiscordLinkTicket,
  issueDiscordLinkTicket,
} from "./discord-link.js";
import {
  discordLinkPageCss,
  discordLinkPageJavaScript,
  renderDiscordLinkPage,
} from "./discord-link-page.js";
import { discordRoleSyncBody, syncDiscordRoles } from "./discord-role-sync.js";
import { validInternalBearer } from "./internal-auth.js";
import {
  consumeLoginTicket,
  issueLoginTicket,
  provisionLegacyUser,
} from "./login-ticket.js";
import {
  beginPasskeyAuthentication,
  finishPasskeyAuthentication,
} from "./passkey-authentication.js";
import {
  loginPageCss,
  loginPageJavaScript,
  renderLoginPage,
} from "./login-page.js";

type AppOptions = {
  internalToken: string;
  identityBridgeToken?: string;
  oidcProvider?: Provider;
  oidcIssuer?: string;
  legacyLoginUrl?: string;
  loginMode?: "legacy_bridge" | "passkey";
  trustProxy?: boolean;
  loginTickets?: {
    provision: typeof provisionLegacyUser;
    issue: typeof issueLoginTicket;
    consume: typeof consumeLoginTicket;
  };
  passkeys?: {
    begin: typeof beginPasskeyAuthentication;
    finish: typeof finishPasskeyAuthentication;
  };
  discordLinks?: {
    issue: typeof issueDiscordLinkTicket;
    inspect: typeof inspectDiscordLinkTicket;
    complete: typeof completeDiscordLink;
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
const passkeyOptionsBody = z.object({
  email: z.string().trim().email().max(320).optional(),
});
const passkeyResponse = z.object({ id: z.string().min(1) }).passthrough();
const passkeyVerifyBody = z.object({
  challengeId: z.string().uuid(),
  response: passkeyResponse,
});
const discordLinkTicket = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const discordLinkTicketBody = z.object({
  discordUserId: z.string().regex(/^\d{17,20}$/),
  discordGuildId: z.string().regex(/^\d{17,20}$/),
});
const discordLinkPasskeyOptionsBody = z.object({
  ticket: discordLinkTicket,
  email: z.string().trim().email().max(320).optional(),
});
const discordLinkPasskeyVerifyBody = z.object({
  ticket: discordLinkTicket,
  challengeId: z.string().uuid(),
  response: passkeyResponse,
});

const passkeyAuthenticationErrors = new Set([
  "invalid_or_expired_challenge",
  "unknown_passkey",
  "passkey_verification_failed",
  "passkey_counter_changed",
]);

function requestHasExpectedOrigin(origin: string | undefined, issuer: string | undefined) {
  if (!origin || !issuer) return false;
  try {
    return new URL(origin).origin === new URL(issuer).origin;
  } catch {
    return false;
  }
}

function protectDiscordLinkPage(reply: { header(name: string, value: string): unknown }) {
  reply.header("Cache-Control", "no-store");
  reply.header("Referrer-Policy", "no-referrer");
  reply.header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
}

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

  const passkeys = options.passkeys ?? {
    begin: beginPasskeyAuthentication,
    finish: finishPasskeyAuthentication,
  };
  const discordLinks = options.discordLinks ?? {
    issue: issueDiscordLinkTicket,
    inspect: inspectDiscordLinkTicket,
    complete: completeDiscordLink,
  };

  app.get("/", async () => ({
    service: "LH-SSO",
    version: "1.3.0",
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

  app.get("/assets/login.css", async (_request, reply) => reply
    .header("Cache-Control", "public, max-age=300")
    .type("text/css; charset=utf-8")
    .send(loginPageCss));
  app.get("/assets/login.js", async (_request, reply) => reply
    .header("Cache-Control", "public, max-age=300")
    .type("text/javascript; charset=utf-8")
    .send(loginPageJavaScript));
  app.get("/assets/discord-link.css", async (_request, reply) => reply
    .header("Cache-Control", "public, max-age=300")
    .type("text/css; charset=utf-8")
    .send(discordLinkPageCss));
  app.get("/assets/discord-link.js", async (_request, reply) => reply
    .header("Cache-Control", "public, max-age=300")
    .type("text/javascript; charset=utf-8")
    .send(discordLinkPageJavaScript));

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

  app.post("/internal/discord/link-tickets", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    if (!validInternalBearer(request.headers.authorization, options.internalToken)) {
      return reply.status(401).send({ error: "invalid_internal_token" });
    }
    if (!options.oidcIssuer) return reply.status(503).send({ error: "identity_service_unavailable" });
    const body = discordLinkTicketBody.safeParse(request.body);
    if (!body.success) return reply.status(400).send({ error: "validation_error" });
    try {
      const issued = await discordLinks.issue(body.data);
      return reply.status(201).send({
        data: {
          linkUrl: `${options.oidcIssuer}/discord/link#ticket=${encodeURIComponent(issued.ticket)}`,
          expiresIn: issued.expiresIn,
        },
      });
    } catch (error) {
      if (error instanceof Error && error.message === "discord_staff_role_required") {
        return reply.status(409).send({ error: "discord_staff_role_required" });
      }
      throw error;
    }
  });

  app.get("/discord/link", async (_request, reply) => {
    protectDiscordLinkPage(reply);
    return reply.type("text/html; charset=utf-8").send(renderDiscordLinkPage());
  });

  app.post(
    "/discord/link/passkey/options",
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      if (!requestHasExpectedOrigin(request.headers.origin, options.oidcIssuer)) {
        return reply.status(403).send({ error: "invalid_origin" });
      }
      const body = discordLinkPasskeyOptionsBody.safeParse(request.body);
      if (!body.success) return reply.status(400).send({ error: "validation_error" });
      const link = await discordLinks.inspect(body.data.ticket);
      if (!link) return reply.status(410).send({ error: "invalid_or_expired_link" });
      try {
        return {
          data: await passkeys.begin(discordLinkInteractionUid(link.id), body.data.email),
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : "authentication_failed";
        if (["account_not_found", "passkey_not_registered"].includes(message)) {
          return reply.status(400).send({ error: "authentication_failed" });
        }
        throw error;
      }
    },
  );

  app.post(
    "/discord/link/passkey/verify",
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
      reply.header("Cache-Control", "no-store");
      if (!requestHasExpectedOrigin(request.headers.origin, options.oidcIssuer)) {
        return reply.status(403).send({ error: "invalid_origin" });
      }
      const body = discordLinkPasskeyVerifyBody.safeParse(request.body);
      if (!body.success) return reply.status(400).send({ error: "validation_error" });
      const link = await discordLinks.inspect(body.data.ticket);
      if (!link) return reply.status(410).send({ error: "invalid_or_expired_link" });
      try {
        const authentication = await passkeys.finish({
          interactionUid: discordLinkInteractionUid(link.id),
          challengeId: body.data.challengeId,
          response: body.data.response as unknown as AuthenticationResponseJSON,
        });
        return {
          data: await discordLinks.complete(body.data.ticket, authentication.subject),
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : "authentication_failed";
        if (passkeyAuthenticationErrors.has(message) || message === "account_not_found") {
          return reply.status(401).send({ error: "authentication_failed" });
        }
        if (message === "invalid_or_expired_discord_link") {
          return reply.status(410).send({ error: "invalid_or_expired_link" });
        }
        if (["discord_identity_already_linked", "sso_account_already_linked"].includes(message)) {
          return reply.status(409).send({ error: "discord_link_conflict" });
        }
        if (message === "discord_staff_role_required") {
          return reply.status(403).send({ error: "discord_staff_role_required" });
        }
        throw error;
      }
    },
  );

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
    const loginMode = options.loginMode ?? "legacy_bridge";

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
          if (loginMode === "passkey") {
            return reply.type("text/html; charset=utf-8").send(renderLoginPage(details.uid));
          }
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
      "/interaction/:uid/passkey/options",
      {
        schema: { params: interactionParams },
        config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
      },
      async (request, reply) => {
        reply.header("Cache-Control", "no-store");
        if (loginMode !== "passkey") return reply.status(404).send({ error: "not_found" });
        const details = await provider.interactionDetails(request.raw, reply.raw);
        if (details.uid !== request.params.uid || details.prompt.name !== "login") {
          return reply.status(400).send({ error: "interaction_mismatch" });
        }
        const body = passkeyOptionsBody.safeParse(request.body ?? {});
        if (!body.success) return reply.status(400).send({ error: "validation_error" });
        try {
          return { data: await passkeys.begin(request.params.uid, body.data.email) };
        } catch (error) {
          const message = error instanceof Error ? error.message : "authentication_failed";
          if (["account_not_found", "passkey_not_registered"].includes(message)) {
            return reply.status(400).send({ error: "authentication_failed" });
          }
          throw error;
        }
      },
    );

    app.post<{ Params: { uid: string } }>(
      "/interaction/:uid/passkey/verify",
      {
        schema: { params: interactionParams },
        config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
      },
      async (request, reply) => {
        reply.header("Cache-Control", "no-store");
        if (loginMode !== "passkey") return reply.status(404).send({ error: "not_found" });
        const details = await provider.interactionDetails(request.raw, reply.raw);
        if (details.uid !== request.params.uid || details.prompt.name !== "login") {
          return reply.status(400).send({ error: "interaction_mismatch" });
        }
        const body = passkeyVerifyBody.safeParse(request.body);
        if (!body.success) return reply.status(400).send({ error: "validation_error" });
        try {
          const authentication = await passkeys.finish({
            interactionUid: request.params.uid,
            challengeId: body.data.challengeId,
            response: body.data.response as unknown as AuthenticationResponseJSON,
          });
          const issued = await tickets.issue(
            request.params.uid,
            authentication.subject,
            "passkey",
          );
          if (!issued) return reply.status(404).send({ error: "account_not_found" });
          return {
            data: {
              ...issued,
              completionUri: `${options.oidcIssuer}/interaction/${request.params.uid}/complete`,
            },
          };
        } catch (error) {
          const message = error instanceof Error ? error.message : "authentication_failed";
          if (passkeyAuthenticationErrors.has(message)) {
            return reply.status(401).send({ error: "authentication_failed" });
          }
          throw error;
        }
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
        const login = await tickets.consume(ticket, request.params.uid);
        if (!login) return reply.status(401).send({ error: "invalid_login_ticket" });
        reply.hijack();
        await provider.interactionFinished(request.raw, reply.raw, {
          login: {
            accountId: login.subject,
            acr: login.authenticationMethod === "passkey"
              ? "urn:legacyhosting:identity:passkey"
              : "urn:legacyhosting:identity:legacy-panel",
            amr: [login.authenticationMethod],
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
