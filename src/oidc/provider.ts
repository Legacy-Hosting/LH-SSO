import Provider, {
  errors,
  type AdapterConstructor,
  type Configuration,
  type FindAccount,
} from "oidc-provider";
import { accountClaims, findSsoAccount } from "./accounts.js";
import { MySqlOidcAdapter } from "./mysql-adapter.js";
import type { OidcRuntimeConfig } from "./runtime-config.js";
import { verifyLogoutHint } from "./logout-hint.js";

function escapeHtml(value: string) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function logoutDocument(input: { form?: string; automatic?: boolean; complete?: boolean }) {
  const form = input.form?.replace(
    "</form>",
    `${input.automatic ? '<input type="hidden" name="logout" value="yes">' : ""}${input.automatic ? "" : '<div class="actions"><button class="secondary" type="submit">Stay signed in</button><button class="primary" name="logout" value="yes" type="submit">Sign out</button></div>'}</form>`,
  ) ?? "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>${input.complete ? "Signed out" : "Sign out"} · Legacy Hosting</title><style>
    :root{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#e9eaf2;background:#0b0c10;color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% 0,#211d3b 0,#0b0c10 45%)}main{width:min(430px,100%);padding:34px;border:1px solid #322d50;border-radius:16px;background:#14151b;box-shadow:0 30px 90px rgba(0,0,0,.4)}.logo{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;background:#7561ff;font-weight:800}span{display:block;margin-top:24px;color:#a99aff;font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}h1{margin:8px 0 0;font-size:27px}p{margin:11px 0 0;color:#9b9eac;font-size:13px;line-height:1.6}.actions{margin-top:27px;display:flex;justify-content:flex-end;gap:9px}button{min-height:40px;padding:0 15px;border-radius:8px;font:inherit;font-size:12px;font-weight:700;cursor:pointer}.secondary{border:1px solid #343741;color:#d9dbe4;background:#181a21}.primary{border:0;color:#fff;background:#7561ff}.progress{margin-top:25px;color:#858795;font-size:11px}.progress i{display:inline-block;width:7px;height:7px;margin-right:8px;border-radius:50%;background:#55dda3}
  </style></head><body><main><div class="logo">L</div><span>Legacy Hosting SSO</span><h1>${input.complete ? "You are signed out" : input.automatic ? "Signing you out" : "Confirm sign out"}</h1><p>${input.complete ? "Your central Legacy Hosting session has been closed." : input.automatic ? "Closing your central session and returning you to the application." : "Only continue if you intended to end your Legacy Hosting session."}</p>${form}${input.automatic ? '<div class="progress"><i></i>Finishing secure sign-out</div><script>document.getElementById("op.logoutForm").submit()</script>' : ""}</main></body></html>`;
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
      backchannelLogout: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource(context, form) {
          const clientId = context.oidc.client?.clientId;
          const params = context.oidc.params ?? {};
          const redirectUri = params.post_logout_redirect_uri;
          const hint = params.logout_hint;
          const client = runtime.clients.find((candidate) => candidate.client_id === clientId);
          const automatic = typeof clientId === "string"
            && typeof redirectUri === "string"
            && typeof hint === "string"
            && typeof client?.client_secret === "string"
            && verifyLogoutHint({
              hint,
              audience: runtime.issuer,
              clientId,
              clientSecret: client.client_secret,
              redirectUri,
            });
          context.set("Referrer-Policy", "no-referrer");
          context.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'");
          context.type = "html";
          context.body = logoutDocument({ form, automatic });
        },
        postLogoutSuccessSource(context) {
          context.set("Referrer-Policy", "no-referrer");
          context.set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'");
          context.type = "html";
          context.body = logoutDocument({ complete: true });
        },
      },
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
      return claims
        ? {
            name: claims.name,
            ...(claims.email
              ? { email: claims.email, email_verified: claims.email_verified }
              : {}),
            roles: claims.roles,
          }
        : undefined;
    },
    cookies: {
      keys: runtime.cookieKeys,
      names: runtime.production
        ? {
            session: "__Host-lh_sso_session",
            interaction: "__Host-lh_sso_interaction",
            // oidc-provider scopes this cookie to /auth/<interaction-id>.
            // __Host- cookies require Path=/ and would be rejected by browsers.
            resume: "__Secure-lh_sso_resume",
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
