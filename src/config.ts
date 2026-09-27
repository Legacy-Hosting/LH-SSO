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
    TRUST_PROXY: booleanFromString,
    DATABASE_URL: z.string().min(1).optional(),
    DATABASE_SSL_CA: z.string().min(1).optional(),
    DATABASE_CONNECT_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(30_000).default(5_000),
    LH_DISCORD_INTERNAL_TOKEN: z.string().min(32).optional(),
  })
  .superRefine((value, context) => {
    if (value.NODE_ENV !== "production") return;
    for (const key of [
      "DATABASE_URL",
      "DATABASE_SSL_CA",
      "LH_DISCORD_INTERNAL_TOKEN",
    ] as const) {
      if (!value[key]) {
        context.addIssue({
          code: "custom",
          path: [key],
          message: `${key} is required in production`,
        });
      }
    }
  })
  .parse(process.env);
