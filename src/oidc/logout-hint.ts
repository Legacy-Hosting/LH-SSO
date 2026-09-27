import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

const payloadSchema = z.object({
  v: z.literal(1),
  aud: z.string().url().max(500),
  clientId: z.string().min(1).max(64),
  redirectUri: z.string().url().max(1_024),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
});

export function verifyLogoutHint(input: {
  hint: string | undefined;
  audience: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  now?: () => number;
}) {
  if (!input.hint || input.hint.length > 4_096) return false;
  const segments = input.hint.split(".");
  if (segments.length !== 2 || !segments[0] || !segments[1]) return false;
  const expected = createHmac("sha256", input.clientSecret)
    .update(segments[0], "utf8")
    .digest();
  let received: Buffer;
  try {
    received = Buffer.from(segments[1], "base64url");
  } catch {
    return false;
  }
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) return false;
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(segments[0], "base64url").toString("utf8"));
  } catch {
    return false;
  }
  const parsed = payloadSchema.safeParse(payload);
  if (!parsed.success) return false;
  const timestamp = Math.floor((input.now ?? Date.now)() / 1_000);
  return parsed.data.aud === input.audience
    && parsed.data.clientId === input.clientId
    && parsed.data.redirectUri === input.redirectUri
    && parsed.data.iat >= timestamp - 10
    && parsed.data.iat <= timestamp + 5
    && parsed.data.exp >= timestamp
    && parsed.data.exp <= parsed.data.iat + 60;
}
