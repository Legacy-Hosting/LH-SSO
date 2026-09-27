import { readFileSync } from "node:fs";
import type { ClientMetadata, JWKS } from "oidc-provider";
import { z } from "zod";
import { config } from "../config.js";

const absoluteUrl = z.string().url();

const clientSchema = z
  .object({
    client_id: z.string().regex(/^[a-z0-9][a-z0-9_-]{2,63}$/),
    client_secret: z.string().min(32).optional(),
    client_name: z.string().min(1).max(100).optional(),
    redirect_uris: z.array(absoluteUrl).min(1).max(10),
    post_logout_redirect_uris: z.array(absoluteUrl).max(10).optional(),
    backchannel_logout_uri: absoluteUrl.optional(),
    backchannel_logout_session_required: z.boolean().optional(),
    grant_types: z
      .array(z.enum(["authorization_code", "refresh_token"]))
      .min(1)
      .refine((values) => values.includes("authorization_code")),
    response_types: z.tuple([z.literal("code")]),
    token_endpoint_auth_method: z.enum(["client_secret_basic", "none"]),
    id_token_signed_response_alg: z.literal("ES256").default("ES256"),
    lh_resource: absoluteUrl,
  })
  .superRefine((client, context) => {
    if (client.token_endpoint_auth_method === "client_secret_basic" && !client.client_secret) {
      context.addIssue({
        code: "custom",
        path: ["client_secret"],
        message: "confidential clients require a client secret",
      });
    }
    if (client.token_endpoint_auth_method === "none" && client.client_secret) {
      context.addIssue({
        code: "custom",
        path: ["client_secret"],
        message: "public clients must not have a client secret",
      });
    }
    if (client.backchannel_logout_session_required && !client.backchannel_logout_uri) {
      context.addIssue({
        code: "custom",
        path: ["backchannel_logout_uri"],
        message: "backchannel logout session tracking requires a logout URI",
      });
    }
  });

const resourceSchema = z.object({
  identifier: absoluteUrl,
  audience: z.string().min(1).max(200),
  scopes: z.array(z.string().regex(/^[a-z][a-z0-9:_-]{0,63}$/)).min(1).max(20),
});

const jwksSchema = z.object({
  keys: z
    .array(
      z
        .object({
          kid: z.string().min(1),
          kty: z.literal("EC"),
          crv: z.literal("P-256"),
          use: z.literal("sig").optional(),
          alg: z.literal("ES256"),
          d: z.string().min(1),
        })
        .passthrough(),
    )
    .min(1),
});

export type OidcResource = z.infer<typeof resourceSchema>;

export type OidcRuntimeConfig = {
  issuer: string;
  port: number;
  cookieKeys: string[];
  clients: ClientMetadata[];
  resources: Map<string, OidcResource>;
  jwks: JWKS;
  legacyLoginUrl: string;
  production: boolean;
};

function parseJson(value: string, name: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${name} must contain valid JSON`);
  }
}

function requireValue(value: string | undefined, name: string) {
  if (!value) throw new Error(`${name} is required to start the OIDC provider`);
  return value;
}

function assertUnique(values: string[], name: string) {
  if (new Set(values).size !== values.length) throw new Error(`${name} must be unique`);
}

function assertRedirectSecurity(urls: string[], production: boolean) {
  for (const value of urls) {
    const url = new URL(value);
    const localDevelopment = !production && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
    if (url.protocol !== "https:" && !(localDevelopment && url.protocol === "http:")) {
      throw new Error(`OIDC redirect URI must use HTTPS: ${value}`);
    }
    if (url.hash) throw new Error(`OIDC redirect URI must not contain a fragment: ${value}`);
  }
}

export function parseOidcRuntimeConfig(input: {
  issuer: string;
  port: number;
  cookieKeysJson: string;
  clientsJson: string;
  resourcesJson: string;
  jwks: unknown;
  legacyLoginUrl: string;
  production: boolean;
}): OidcRuntimeConfig {
  const issuer = new URL(input.issuer);
  if (input.production && issuer.protocol !== "https:") {
    throw new Error("OIDC_ISSUER must use HTTPS in production");
  }
  if (issuer.pathname !== "/") throw new Error("OIDC_ISSUER must not contain a path");
  if (issuer.search || issuer.hash) throw new Error("OIDC_ISSUER cannot contain query or fragment data");

  const cookieKeys = z.array(z.string().min(32)).min(2).max(5).parse(
    parseJson(input.cookieKeysJson, "OIDC_COOKIE_KEYS_JSON"),
  );
  assertUnique(cookieKeys, "OIDC cookie keys");

  const parsedClients = z.array(clientSchema).min(1).max(20).parse(
    parseJson(input.clientsJson, "OIDC_CLIENTS_JSON"),
  );
  assertUnique(parsedClients.map((client) => client.client_id), "OIDC client IDs");

  const parsedResources = z.array(resourceSchema).min(1).max(20).parse(
    parseJson(input.resourcesJson, "OIDC_RESOURCES_JSON"),
  );
  assertUnique(parsedResources.map((resource) => resource.identifier), "OIDC resource identifiers");
  assertUnique(parsedResources.map((resource) => resource.audience), "OIDC resource audiences");
  const resources = new Map(parsedResources.map((resource) => [resource.identifier, resource]));
  if (input.production) {
    for (const resource of parsedResources) {
      if (new URL(resource.identifier).protocol !== "https:") {
        throw new Error(`OIDC resource identifier must use HTTPS: ${resource.identifier}`);
      }
    }
  }

  for (const client of parsedClients) {
    assertRedirectSecurity(
      [
        ...client.redirect_uris,
        ...(client.post_logout_redirect_uris ?? []),
        ...(client.backchannel_logout_uri ? [client.backchannel_logout_uri] : []),
      ],
      input.production,
    );
    if (!resources.has(client.lh_resource)) {
      throw new Error(`OIDC client ${client.client_id} references an unknown lh_resource`);
    }
  }

  const jwks = jwksSchema.parse(input.jwks);
  assertUnique(jwks.keys.map((key) => key.kid), "OIDC signing key IDs");

  const legacyLoginUrl = new URL(input.legacyLoginUrl);
  if (input.production && legacyLoginUrl.protocol !== "https:") {
    throw new Error("OIDC_LEGACY_LOGIN_URL must use HTTPS in production");
  }
  if (legacyLoginUrl.hash) throw new Error("OIDC_LEGACY_LOGIN_URL must not contain a fragment");

  return {
    issuer: issuer.toString().replace(/\/$/, ""),
    port: input.port,
    cookieKeys,
    clients: parsedClients as ClientMetadata[],
    resources,
    jwks: jwks as JWKS,
    legacyLoginUrl: legacyLoginUrl.toString(),
    production: input.production,
  };
}

export function loadOidcRuntimeConfig(): OidcRuntimeConfig {
  const jwksFile = requireValue(config.OIDC_JWKS_FILE, "OIDC_JWKS_FILE");
  return parseOidcRuntimeConfig({
    issuer: requireValue(config.OIDC_ISSUER, "OIDC_ISSUER"),
    port: config.OIDC_PORT,
    cookieKeysJson: requireValue(config.OIDC_COOKIE_KEYS_JSON, "OIDC_COOKIE_KEYS_JSON"),
    clientsJson: requireValue(config.OIDC_CLIENTS_JSON, "OIDC_CLIENTS_JSON"),
    resourcesJson: requireValue(config.OIDC_RESOURCES_JSON, "OIDC_RESOURCES_JSON"),
    jwks: parseJson(readFileSync(jwksFile, "utf8"), "OIDC_JWKS_FILE"),
    legacyLoginUrl: requireValue(config.OIDC_LEGACY_LOGIN_URL, "OIDC_LEGACY_LOGIN_URL"),
    production: config.NODE_ENV === "production",
  });
}
