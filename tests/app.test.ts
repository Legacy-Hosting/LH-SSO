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
