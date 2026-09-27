import assert from "node:assert/strict";
import { test } from "node:test";
import type Provider from "oidc-provider";
import { createApp } from "../src/app.js";

const internalToken = "i".repeat(32);
const bridgeToken = "b".repeat(32);

test("identity landing page and social assets are public without exposing configuration", async () => {
  const app = createApp({ internalToken });
  try {
    const page = await app.inject({ method: "GET", url: "/" });
    assert.equal(page.statusCode, 200);
    assert.match(page.headers["content-type"] ?? "", /text\/html/);
    assert.match(page.body, /Legacy Hosting Identity/);
    assert.match(page.body, /property="og:image"/);
    assert.match(page.body, /name="twitter:card" content="summary_large_image"/);

    const favicon = await app.inject({ method: "GET", url: "/favicon.svg" });
    assert.equal(favicon.statusCode, 200);
    assert.match(favicon.headers["content-type"] ?? "", /image\/svg\+xml/);

    const socialCard = await app.inject({ method: "GET", url: "/social-card.png" });
    assert.equal(socialCard.statusCode, 200);
    assert.match(socialCard.headers["content-type"] ?? "", /image\/png/);
  } finally {
    await app.close();
  }
});

test("readiness returns 503 when the database dependency is unavailable", async () => {
  const app = createApp({
    internalToken,
    databaseStatus: async () => "unavailable",
  });
  try {
    const response = await app.inject({ method: "GET", url: "/health" });
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.json(), {
      status: "degraded",
      database: "unavailable",
    });
  } finally {
    await app.close();
  }
});

test("the login ticket bridge is internal and never authenticates unknown users", async () => {
  const app = createApp({
    internalToken,
    identityBridgeToken: bridgeToken,
    oidcProvider: {
      Interaction: { find: async () => ({}) },
    } as unknown as Provider,
    oidcIssuer: "https://auth.legacyhosting.xyz",
    legacyLoginUrl: "https://panel.legacyhosting.xyz/login",
    loginTickets: {
      provision: async (input) => {
        if (input.email === "conflict@example.com") throw new Error("identity_conflict");
      },
      issue: async (_interactionUid, subject) => subject.startsWith("123e")
        ? { ticket: "t".repeat(43), expiresIn: 60 }
        : undefined,
      consume: async () => undefined,
    },
  });
  try {
    const body = {
      interactionUid: "interaction_uid_123456",
      subject: "123e4567-e89b-12d3-a456-426614174000",
      email: "user@example.com",
      displayName: "Example User",
    };
    const unauthorized = await app.inject({
      method: "POST",
      url: "/internal/oidc/login-tickets",
      payload: body,
    });
    assert.equal(unauthorized.statusCode, 401);

    const response = await app.inject({
      method: "POST",
      url: "/internal/oidc/login-tickets",
      headers: { authorization: `Bearer ${bridgeToken}` },
      payload: body,
    });
    assert.equal(response.statusCode, 201);
    assert.deepEqual(response.json(), {
      data: {
        ticket: "t".repeat(43),
        expiresIn: 60,
        completionUri: "https://auth.legacyhosting.xyz/interaction/interaction_uid_123456/complete",
      },
    });

    const conflict = await app.inject({
      method: "POST",
      url: "/internal/oidc/login-tickets",
      headers: { authorization: `Bearer ${bridgeToken}` },
      payload: { ...body, email: "conflict@example.com" },
    });
    assert.equal(conflict.statusCode, 409);
    assert.equal(conflict.json().error, "identity_conflict");
  } finally {
    await app.close();
  }
});

test("passkey mode serves a same-origin login and issues a passkey-bound ticket", async () => {
  const interactionUid = "interaction_uid_123456";
  let authenticationMethod = "";
  const app = createApp({
    internalToken,
    identityBridgeToken: bridgeToken,
    oidcProvider: {
      Interaction: { find: async () => ({}) },
      interactionDetails: async () => ({
        uid: interactionUid,
        prompt: { name: "login", details: {} },
        params: {},
      }),
    } as unknown as Provider,
    oidcIssuer: "https://auth.legacyhosting.xyz",
    legacyLoginUrl: "https://panel.legacyhosting.xyz/login",
    loginMode: "passkey",
    loginTickets: {
      provision: async () => undefined,
      issue: async (_uid, _subject, method = "legacy_panel") => {
        authenticationMethod = method;
        return { ticket: "t".repeat(43), expiresIn: 60 };
      },
      consume: async () => undefined,
    },
    passkeys: {
      begin: async (_uid, email) => {
        if (email === "unknown@example.com") throw new Error("account_not_found");
        return {
          challengeId: "123e4567-e89b-12d3-a456-426614174000",
          options: { challenge: "c".repeat(43) },
        } as never;
      },
      finish: async (input) => {
        if (input.response.id === "unknown") throw new Error("unknown_passkey");
        return { subject: "123e4567-e89b-12d3-a456-426614174000" };
      },
    },
  });
  try {
    const page = await app.inject({ method: "GET", url: `/interaction/${interactionUid}` });
    assert.equal(page.statusCode, 200);
    assert.match(page.headers["content-type"] ?? "", /text\/html/);
    assert.match(page.body, /\/assets\/login\.js/);
    assert.doesNotMatch(page.body, /<script>(?!<\/script>)/);

    const script = await app.inject({ method: "GET", url: "/assets/login.js" });
    assert.equal(script.statusCode, 200);
    assert.match(script.body, /navigator\.credentials\.get/);

    const started = await app.inject({
      method: "POST",
      url: `/interaction/${interactionUid}/passkey/options`,
      payload: { email: "user@example.com" },
    });
    assert.equal(started.statusCode, 200, started.body);

    const verified = await app.inject({
      method: "POST",
      url: `/interaction/${interactionUid}/passkey/verify`,
      payload: {
        challengeId: "123e4567-e89b-12d3-a456-426614174000",
        response: { id: "credential" },
      },
    });
    assert.equal(verified.statusCode, 200, verified.body);
    assert.equal(authenticationMethod, "passkey");
    assert.equal(verified.json().data.ticket, "t".repeat(43));

    const unknownAccount = await app.inject({
      method: "POST",
      url: `/interaction/${interactionUid}/passkey/options`,
      payload: { email: "unknown@example.com" },
    });
    assert.equal(unknownAccount.statusCode, 400);
    assert.deepEqual(unknownAccount.json(), { error: "authentication_failed" });

    const unknownPasskey = await app.inject({
      method: "POST",
      url: `/interaction/${interactionUid}/passkey/verify`,
      payload: {
        challengeId: "123e4567-e89b-12d3-a456-426614174000",
        response: { id: "unknown" },
      },
    });
    assert.equal(unknownPasskey.statusCode, 401);
    assert.deepEqual(unknownPasskey.json(), { error: "authentication_failed" });
  } finally {
    await app.close();
  }
});

test("Discord account linking is internal to issue and passkey-protected to complete", async () => {
  const ticket = "d".repeat(43);
  const linkId = "123e4567-e89b-12d3-a456-426614174111";
  let completedSubject = "";
  const app = createApp({
    internalToken,
    oidcIssuer: "https://auth.legacyhosting.xyz",
    discordLinks: {
      issue: async () => ({ ticket, expiresIn: 600 }),
      inspect: async (candidate) => candidate === ticket
        ? ({ id: linkId, discordUserId: "92345678901234567", discordGuildId: "82345678901234567" } as never)
        : undefined,
      complete: async (_ticket, subject) => {
        completedSubject = subject;
        return { discordUserId: "92345678901234567", staffRoles: ["developer"] };
      },
    },
    passkeys: {
      begin: async (interactionUid) => {
        assert.equal(interactionUid, "discord_link_123e4567e89b12d3a456426614174111");
        return {
          challengeId: "123e4567-e89b-12d3-a456-426614174222",
          options: { challenge: "c".repeat(43) },
        } as never;
      },
      finish: async (input) => {
        assert.equal(input.interactionUid, "discord_link_123e4567e89b12d3a456426614174111");
        return { subject: "123e4567-e89b-12d3-a456-426614174000" };
      },
    },
  });
  try {
    const unauthorized = await app.inject({
      method: "POST",
      url: "/internal/discord/link-tickets",
      payload: {
        discordUserId: "92345678901234567",
        discordGuildId: "82345678901234567",
      },
    });
    assert.equal(unauthorized.statusCode, 401);

    const issued = await app.inject({
      method: "POST",
      url: "/internal/discord/link-tickets",
      headers: { authorization: `Bearer ${internalToken}` },
      payload: {
        discordUserId: "92345678901234567",
        discordGuildId: "82345678901234567",
      },
    });
    assert.equal(issued.statusCode, 201, issued.body);
    assert.equal(
      issued.json().data.linkUrl,
      `https://auth.legacyhosting.xyz/discord/link#ticket=${ticket}`,
    );

    const page = await app.inject({ method: "GET", url: "/discord/link" });
    assert.equal(page.statusCode, 200);
    assert.match(page.headers["content-security-policy"] ?? "", /default-src 'none'/);
    assert.equal(page.headers["referrer-policy"], "no-referrer");
    assert.doesNotMatch(page.body, new RegExp(ticket));

    const invalidOrigin = await app.inject({
      method: "POST",
      url: "/discord/link/passkey/options",
      headers: { origin: "https://attacker.example" },
      payload: { ticket },
    });
    assert.equal(invalidOrigin.statusCode, 403);

    const started = await app.inject({
      method: "POST",
      url: "/discord/link/passkey/options",
      headers: { origin: "https://auth.legacyhosting.xyz" },
      payload: { ticket },
    });
    assert.equal(started.statusCode, 200, started.body);

    const verified = await app.inject({
      method: "POST",
      url: "/discord/link/passkey/verify",
      headers: { origin: "https://auth.legacyhosting.xyz" },
      payload: {
        ticket,
        challengeId: "123e4567-e89b-12d3-a456-426614174222",
        response: { id: "credential" },
      },
    });
    assert.equal(verified.statusCode, 200, verified.body);
    assert.equal(completedSubject, "123e4567-e89b-12d3-a456-426614174000");
    assert.deepEqual(verified.json().data.staffRoles, ["developer"]);

    const expired = await app.inject({
      method: "POST",
      url: "/discord/link/passkey/options",
      headers: { origin: "https://auth.legacyhosting.xyz" },
      payload: { ticket: "x".repeat(43) },
    });
    assert.equal(expired.statusCode, 410);
  } finally {
    await app.close();
  }
});
