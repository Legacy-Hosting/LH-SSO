import "dotenv/config";
import { z } from "zod";

const booleanFromString = z
  .enum(["true", "false"])
  .default("false")
  .transform((value) => value === "true");

export const config = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    HOST: z.string().default("127.0.0.1"),
    PORT: z.coerce.number().int().positive().default(8080),
    OIDC_PORT: z.coerce.number().int().positive().default(8081),
    TRUST_PROXY: booleanFromString,
    DATABASE_URL: z.string().min(1).optional(),
    DATABASE_SSL_CA: z.string().min(1).optional(),
    LEGACY_DATABASE_URL: z.string().min(1).optional(),
    LEGACY_DATABASE_SSL_CA: z.string().min(1).optional(),
    LEGACY_WEBAUTHN_RP_ID: z.string().min(1).optional(),
    DATABASE_CONNECT_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(30_000).default(5_000),
    LH_DISCORD_INTERNAL_TOKEN: z.string().min(32).optional(),
    LH_IDENTITY_BRIDGE_TOKEN: z.string().min(32).optional(),
    OIDC_ISSUER: z.string().url().optional(),
    OIDC_COOKIE_KEYS_JSON: z.string().min(1).optional(),
    OIDC_JWKS_FILE: z.string().min(1).optional(),
    OIDC_CLIENTS_JSON: z.string().min(1).optional(),
    OIDC_RESOURCES_JSON: z.string().min(1).optional(),
    OIDC_LEGACY_LOGIN_URL: z.string().url().optional(),
    OIDC_LOGIN_MODE: z.enum(["legacy_bridge", "passkey"]).default("legacy_bridge"),
    WEBAUTHN_RP_NAME: z.string().min(1).max(100).default("Legacy Hosting"),
    WEBAUTHN_RP_ID: z.string().min(1).default("localhost"),
    WEBAUTHN_ORIGIN: z.string().url().default("http://localhost:8080"),
  })
  .superRefine((value, context) => {
    if (value.PORT === value.OIDC_PORT) {
      context.addIssue({
        code: "custom",
        path: ["OIDC_PORT"],
        message: "OIDC_PORT must differ from PORT",
      });
    }
    if (
      value.LH_DISCORD_INTERNAL_TOKEN &&
      value.LH_IDENTITY_BRIDGE_TOKEN === value.LH_DISCORD_INTERNAL_TOKEN
    ) {
      context.addIssue({
        code: "custom",
        path: ["LH_IDENTITY_BRIDGE_TOKEN"],
        message: "internal service tokens must be distinct",
      });
    }
    const legacyMigrationKeys = [
      "LEGACY_DATABASE_URL",
      "LEGACY_DATABASE_SSL_CA",
      "LEGACY_WEBAUTHN_RP_ID",
    ] as const;
    if (legacyMigrationKeys.some((key) => value[key])) {
      for (const key of legacyMigrationKeys) {
        if (!value[key]) {
          context.addIssue({
            code: "custom",
            path: [key],
            message: `${key} is required when legacy passkey migration is configured`,
          });
        }
      }
    }
    if (value.NODE_ENV !== "production") return;
    if (value.HOST !== "127.0.0.1") {
      context.addIssue({
        code: "custom",
        path: ["HOST"],
        message: "HOST must be 127.0.0.1 in production",
      });
    }
    for (const key of [
      "DATABASE_URL",
      "DATABASE_SSL_CA",
      "LH_DISCORD_INTERNAL_TOKEN",
      "LH_IDENTITY_BRIDGE_TOKEN",
      "OIDC_ISSUER",
      "OIDC_COOKIE_KEYS_JSON",
      "OIDC_JWKS_FILE",
      "OIDC_CLIENTS_JSON",
      "OIDC_RESOURCES_JSON",
      "OIDC_LEGACY_LOGIN_URL",
    ] as const) {
      if (!value[key]) {
        context.addIssue({
          code: "custom",
          path: [key],
          message: `${key} is required in production`,
        });
      }
    }
    const webauthnOrigin = new URL(value.WEBAUTHN_ORIGIN);
    if (webauthnOrigin.protocol !== "https:") {
      context.addIssue({
        code: "custom",
        path: ["WEBAUTHN_ORIGIN"],
        message: "WEBAUTHN_ORIGIN must use HTTPS in production",
      });
    }
    if (
      webauthnOrigin.hostname !== value.WEBAUTHN_RP_ID &&
      !webauthnOrigin.hostname.endsWith(`.${value.WEBAUTHN_RP_ID}`)
    ) {
      context.addIssue({
        code: "custom",
        path: ["WEBAUTHN_RP_ID"],
        message: "WEBAUTHN_RP_ID must be the WebAuthn origin host or a registrable parent",
      });
    }
  })
  .parse(process.env);
