import Provider, {
  errors,
  type AdapterConstructor,
  type Configuration,
  type FindAccount,
} from "oidc-provider";
import { accountClaims, findSsoAccount } from "./accounts.js";
import { MySqlOidcAdapter } from "./mysql-adapter.js";
import type { OidcRuntimeConfig } from "./runtime-config.js";

function escapeHtml(value: string) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

type ProviderOptions = {
  adapter?: AdapterConstructor | false;
  findAccount?: FindAccount;
  claimsForSubject?: typeof accountClaims;
};

export function createOidcProvider(runtime: OidcRuntimeConfig, options: ProviderOptions = {}) {
  const resourceForClient = (client: { [key: string]: unknown }) => {
    const identifier = client.lh_resource;
    return typeof identifier === "string" ? runtime.resources.get(identifier) : undefined;
  };
  const claimsForSubject = options.claimsForSubject ?? accountClaims;

  const configuration: Configuration = {
    ...(options.adapter === false
      ? {}
      : { adapter: options.adapter ?? MySqlOidcAdapter }),
    clients: runtime.clients,
    clientDefaults: { id_token_signed_response_alg: "ES256" },
    jwks: runtime.jwks,
    findAccount: options.findAccount ?? findSsoAccount,
    claims: {
      profile: ["name"],
      email: ["email", "email_verified"],
      roles: ["roles"],
    },
    scopes: ["openid", "profile", "email", "roles", "offline_access"],
    responseTypes: ["code"],
    clientAuthMethods: ["client_secret_basic", "none"],
    subjectTypes: ["public"],
    pkce: { required: () => true },
    features: {
      devInteractions: { enabled: false },
      userinfo: { enabled: true },
      revocation: { enabled: true },
      resourceIndicators: {
        enabled: true,
        getResourceServerInfo(_context, identifier, client) {
          const resource = runtime.resources.get(identifier);
          if (!resource || resourceForClient(client) !== resource) {
            throw new errors.InvalidTarget("client is not allowed to request this resource");
          }
          return {
            scope: resource.scopes.join(" "),
            audience: resource.audience,
            accessTokenTTL: 300,
            accessTokenFormat: "jwt",
            jwt: { sign: { alg: "ES256" } },
          };
        },
        defaultResource(_context, client, oneOf) {
          const resource = resourceForClient(client);
          if (!resource) return undefined;
          if (oneOf && !oneOf.includes(resource.identifier)) return undefined;
          return resource.identifier;
        },
        useGrantedResource: () => true,
      },
    },
    extraClientMetadata: {
      properties: ["lh_resource"],
      validator(_context, key, value) {
        if (key !== "lh_resource" || typeof value !== "string" || !runtime.resources.has(value)) {
          throw new errors.InvalidClientMetadata("lh_resource must identify a configured resource");
        }
      },
    },
    extraTokenClaims: async (_context, token) => {
      const accountId = "accountId" in token && typeof token.accountId === "string"
        ? token.accountId
        : undefined;
      if (!accountId) return undefined;
      const claims = await claimsForSubject(accountId);
      return claims ? { roles: claims.roles } : undefined;
    },
    cookies: {
      keys: runtime.cookieKeys,
      names: runtime.production
        ? {
            session: "__Host-lh_sso_session",
            interaction: "__Host-lh_sso_interaction",
            resume: "__Host-lh_sso_resume",
          }
        : {
            session: "lh_sso_session",
            interaction: "lh_sso_interaction",
            resume: "lh_sso_resume",
          },
      long: {
        httpOnly: true,
        sameSite: "lax",
        secure: runtime.production,
        signed: true,
        path: "/",
      },
      short: {
        httpOnly: true,
        sameSite: "lax",
        secure: runtime.production,
        signed: true,
        path: "/",
      },
    },
    ttl: {
      AccessToken: 300,
      AuthorizationCode: 60,
      IdToken: 300,
      Interaction: 600,
      RefreshToken: 28_800,
      Session: 28_800,
      Grant: 28_800,
    },
    rotateRefreshToken: true,
    clockTolerance: 5,
    acceptQueryParamAccessTokens: false,
    allowOmittingSingleRegisteredRedirectUri: false,
    clientBasedCORS: () => false,
    renderError(context, out) {
      context.type = "html";
      context.body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorization failed</title></head><body><main><h1>Authorization failed</h1><p>${escapeHtml(out.error)}</p><p>${escapeHtml(out.error_description ?? "The authorization request could not be completed.")}</p></main></body></html>`;
    },
    interactions: {
      url: (_context, interaction) => `/interaction/${interaction.uid}`,
    },
  };

  const provider = new Provider(runtime.issuer, configuration);
  provider.proxy = true;
  provider.on("server_error", (_context, error) => {
    console.error("OIDC server error", error);
  });
  return provider;
}
