import { generateKeyPairSync, randomUUID } from "node:crypto";
import { existsSync, lstatSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const [outputArgument, option] = process.argv.slice(2);
if (!outputArgument || (option && option !== "--rotate")) {
  console.error("Usage: pnpm oidc:generate-keys OUTPUT_FILE [--rotate]");
  process.exit(2);
}

const output = resolve(outputArgument);
const rotating = option === "--rotate";
if (existsSync(output) && !rotating) {
  throw new Error(`Refusing to overwrite existing key set: ${output}`);
}
if (existsSync(output) && !lstatSync(output).isFile()) {
  throw new Error(`OIDC key path must be a regular file: ${output}`);
}

function newSigningKey() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    ...privateKey.export({ format: "jwk" }),
    kid: randomUUID(),
    use: "sig",
    alg: "ES256",
  };
}

let keys;
if (rotating) {
  const current = JSON.parse(readFileSync(output, "utf8"));
  if (!Array.isArray(current.keys) || current.keys.length === 0) {
    throw new Error("Existing OIDC key set is invalid");
  }
  keys = [newSigningKey(), ...current.keys].slice(0, 3);
} else {
  keys = [newSigningKey(), newSigningKey()];
}

const temporary = resolve(dirname(output), `.${randomUUID()}.tmp`);
writeFileSync(temporary, `${JSON.stringify({ keys }, null, 2)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600,
});
renameSync(temporary, output);
console.log(`${rotating ? "Rotated" : "Created"} OIDC signing key set at ${output}`);
