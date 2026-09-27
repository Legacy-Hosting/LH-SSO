import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { test } from "node:test";
import type { Account, Interaction, JWKS } from "oidc-provider";
import { createOidcProvider } from "../src/oidc/provider.js";
import { parseOidcRuntimeConfig, type OidcRuntimeConfig } from "../src/oidc/runtime-config.js";

function signingKeys(): JWKS {
  const keys = ["current", "previous"].map((kid) => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    return { ...privateKey.export({ format: "jwk" }), kid, use: "sig", alg: "ES256" };
  });
  return { keys } as JWKS;
}

function runtime(
  issuer = "http://127.0.0.1",
  production = false,
): OidcRuntimeConfig {
  return parseOidcRuntimeConfig({
    issuer,
    port: 0,
    production,
    cookieKeysJson: JSON.stringify(["a".repeat(32), "b".repeat(32)]),
    clientsJson: JSON.stringify([
      {
        client_id: "test-client",
        redirect_uris: ["https://client.example/callback"],
        post_logout_redirect_uris: ["https://client.example/"],
        backchannel_logout_uri: "https://client.example/backchannel-logout",
        backchannel_logout_session_required: true,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        lh_resource: "https://hub.legacyhosting.xyz",
      },
    ]),
    resourcesJson: JSON.stringify([
      {
        identifier: "https://hub.legacyhosting.xyz",
        audience: "lh-hub",
        scopes: ["openid", "profile", "roles"],
      },
    ]),
    jwks: signingKeys(),
    legacyLoginUrl: production
      ? "https://panel.legacyhosting.xyz/login"
      : "http://127.0.0.1/login",
  });
}

function addConsent(grant: InstanceType<ReturnType<typeof createOidcProvider>["Grant"]>, interaction: Interaction) {
  const details = interaction.prompt.details;
  if (Array.isArray(details.missingOIDCScope)) {
    grant.addOIDCScope(details.missingOIDCScope.join(" "));
  }
  if (Array.isArray(details.missingOIDCClaims)) {
    grant.addOIDCClaims(details.missingOIDCClaims as string[]);
  }
  if (details.missingResourceScopes && typeof details.missingResourceScopes === "object") {
    for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
      if (Array.isArray(scopes)) grant.addResourceScope(indicator, scopes.join(" "));
    }
  }
}

test("production OIDC configuration rejects unsafe redirects and unknown resources", () => {
  const base = {
    issuer: "https://auth.legacyhosting.xyz",
    port: 8081,
    production: true,
    cookieKeysJson: JSON.stringify(["a".repeat(32), "b".repeat(32)]),
    resourcesJson: JSON.stringify([
      { identifier: "https://api.legacyhosting.xyz", audience: "lh-api", scopes: ["openid"] },
    ]),
    jwks: signingKeys(),
    legacyLoginUrl: "https://panel.legacyhosting.xyz/login",
  };
  assert.throws(
    () => parseOidcRuntimeConfig({
      ...base,
      clientsJson: JSON.stringify([
        {
          client_id: "unsafe-client",
          redirect_uris: ["http://panel.legacyhosting.xyz/callback"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          lh_resource: "https://api.legacyhosting.xyz",
        },
      ]),
    }),
    /must use HTTPS/,
  );
  assert.throws(
    () => parseOidcRuntimeConfig({
      ...base,
      clientsJson: JSON.stringify([
        {
          client_id: "unknown-resource",
          redirect_uris: ["https://panel.legacyhosting.xyz/callback"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          lh_resource: "https://unknown.legacyhosting.xyz",
        },
      ]),
    }),
    /unknown lh_resource/,
  );
  assert.throws(
    () => parseOidcRuntimeConfig({
      ...base,
      clientsJson: JSON.stringify([
        {
          client_id: "unsafe-logout-client",
          redirect_uris: ["https://panel.legacyhosting.xyz/callback"],
          backchannel_logout_uri: "http://api.legacyhosting.xyz/logout",
          backchannel_logout_session_required: true,
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          lh_resource: "https://api.legacyhosting.xyz",
        },
      ]),
    }),
    /must use HTTPS/,
  );
});

test("production interaction cookies use browser-compatible security prefixes", async () => {
  const provider = createOidcProvider(
    runtime("https://auth.legacyhosting.xyz", true),
    { adapter: false },
  );
  const server = provider.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const authorization = new URL(`http://127.0.0.1:${address.port}/auth`);
  authorization.search = new URLSearchParams({
    client_id: "test-client",
    redirect_uri: "https://client.example/callback",
    response_type: "code",
    scope: "openid profile roles",
    state: "cookie-prefix-test",
    nonce: "cookie-prefix-test-nonce",
    code_challenge: "a".repeat(43),
    code_challenge_method: "S256",
    resource: "https://hub.legacyhosting.xyz",
  }).toString();

  try {
    const response = await fetch(authorization, {
      redirect: "manual",
      headers: { "x-forwarded-proto": "https" },
    });
    assert.equal(response.status, 303);
    const cookies = response.headers.getSetCookie();
    assert.ok(cookies.some((cookie) =>
      cookie.startsWith("__Host-lh_sso_interaction=") && /path=\//i.test(cookie)
    ));
    assert.ok(cookies.some((cookie) =>
      cookie.startsWith("__Secure-lh_sso_resume=") && /path=\/auth\//i.test(cookie)
    ));
    assert.equal(
      cookies.some((cookie) => cookie.startsWith("__Host-lh_sso_resume=")),
      false,
    );
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

test("Authorization Code Flow requires PKCE and issues a short-lived role token", async () => {
  const accountId = "123e4567-e89b-12d3-a456-426614174000";
  const provider = createOidcProvider(runtime(), {
    adapter: false,
    findAccount: async (): Promise<Account> => ({
      accountId,
      claims: async () => ({ sub: accountId, name: "Test User", roles: ["developer"] }),
    }),
    claimsForSubject: async () => ({ sub: accountId, name: "Test User", roles: ["developer"] }),
  });

  provider.use(async (context, next) => {
    if (!context.path.startsWith("/interaction/")) return next();
    const details = await provider.interactionDetails(context.req, context.res);
    context.respond = false;
    if (details.prompt.name === "login") {
      await provider.interactionFinished(context.req, context.res, {
        login: { accountId, amr: ["test"], acr: "urn:test" },
      });
      return;
    }
    assert.equal(details.prompt.name, "consent");
    const grant = details.grantId
      ? await provider.Grant.find(details.grantId)
      : new provider.Grant({ accountId, clientId: String(details.params.client_id) });
    assert.ok(grant);
    addConsent(grant, details);
    await provider.interactionFinished(
      context.req,
      context.res,
      { consent: { grantId: await grant.save() } },
      { mergeWithLastSubmission: true },
    );
  });

  const server = provider.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;
  const cookies = new Map<string, string>();

  async function request(url: string, init: RequestInit = {}) {
    const cookie = [...cookies.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
    const response = await fetch(url, {
      ...init,
      redirect: "manual",
      headers: { ...(cookie ? { cookie } : {}), ...init.headers },
    });
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";", 1)[0];
      const separator = pair?.indexOf("=") ?? -1;
      if (pair && separator > 0) cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
    return response;
  }

  try {
    const discovery = await request(`${origin}/.well-known/openid-configuration`);
    assert.equal(discovery.status, 200);
    const metadata = await discovery.json() as Record<string, unknown>;
    assert.equal(metadata.end_session_endpoint, `${origin}/session/end`);
    assert.equal(metadata.backchannel_logout_supported, true);
    assert.equal(metadata.backchannel_logout_session_supported, true);

    const missingPkce = new URL("/auth", origin);
    missingPkce.search = new URLSearchParams({
      client_id: "test-client",
      redirect_uri: "https://client.example/callback",
      response_type: "code",
      scope: "openid profile roles",
      state: "missing-pkce",
      resource: "https://hub.legacyhosting.xyz",
    }).toString();
    const rejected = await request(missingPkce.toString());
    assert.equal(rejected.status, 303);
    const rejectedLocation = new URL(rejected.headers.get("location")!);
    assert.equal(rejectedLocation.origin, "https://client.example");
    assert.equal(rejectedLocation.searchParams.get("error"), "invalid_request");
    assert.match(rejectedLocation.searchParams.get("error_description") ?? "", /PKCE|code_challenge/i);

    const verifier = "test-verifier-that-is-long-enough-for-pkce-0123456789";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorization = new URL("/auth", origin);
    authorization.search = new URLSearchParams({
      client_id: "test-client",
      redirect_uri: "https://client.example/callback",
      response_type: "code",
      scope: "openid profile roles",
      state: "expected-state",
      nonce: "expected-nonce",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: "https://hub.legacyhosting.xyz",
    }).toString();

    let response = await request(authorization.toString());
    let callback: URL | undefined;
    for (let redirects = 0; redirects < 8; redirects += 1) {
      if (![302, 303].includes(response.status)) {
        assert.fail(`unexpected OIDC response ${response.status}: ${await response.text()}`);
      }
      const location = response.headers.get("location");
      assert.ok(location);
      if (location.startsWith("https://client.example/callback")) {
        callback = new URL(location);
        break;
      }
      response = await request(new URL(location, origin).toString());
    }
    assert.ok(callback);
    assert.equal(callback.searchParams.get("state"), "expected-state");
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const tokenResponse = await request(`${origin}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "test-client",
        redirect_uri: "https://client.example/callback",
        code,
        code_verifier: verifier,
        resource: "https://hub.legacyhosting.xyz",
      }),
    });
    if (tokenResponse.status !== 200) {
      assert.fail(`token endpoint returned ${tokenResponse.status}: ${await tokenResponse.text()}`);
    }
    const tokens = await tokenResponse.json() as Record<string, unknown>;
    assert.equal(tokens.token_type, "Bearer");
    assert.equal(tokens.expires_in, 300);
    assert.equal(typeof tokens.id_token, "string");
    assert.equal(typeof tokens.access_token, "string");
    const accessPayload = JSON.parse(
      Buffer.from(String(tokens.access_token).split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    assert.equal(accessPayload.aud, "lh-hub");
    assert.deepEqual(accessPayload.roles, ["developer"]);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
