import assert from "node:assert/strict";
import { test } from "node:test";
import type Provider from "oidc-provider";
import { createApp } from "../src/app.js";

const internalToken = "i".repeat(32);
const bridgeToken = "b".repeat(32);

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
