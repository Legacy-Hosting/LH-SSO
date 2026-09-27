#!/usr/bin/env bash
set -Eeuo pipefail

base=/opt/legacy-hosting/sso
test -L "$base/current"
test -f "$base/current-release"
curl --fail --silent --show-error http://127.0.0.1:8080/health | \
  grep -q '"database":"connected"'
pm2 describe lh-sso >/dev/null
pm2 describe lh-sso-oidc >/dev/null
curl --fail --silent --show-error http://127.0.0.1:8081/.well-known/openid-configuration | \
  grep -q '"authorization_endpoint"'
current_release=$(readlink -f "$base/current")
recorded_release=$(cat "$base/current-release")
if [[ $recorded_release != "$(basename "$current_release")" ]]; then
  echo "SSO current-release marker does not match the current symlink" >&2
  exit 1
fi
CURRENT_RELEASE="$current_release" node <<'NODE'
const { execFileSync } = require("node:child_process");
const currentRelease = process.env.CURRENT_RELEASE;
const processes = JSON.parse(execFileSync("pm2", ["jlist"], { encoding: "utf8" }));
for (const name of ["lh-sso", "lh-sso-oidc"]) {
  const processInfo = processes.find((item) => item.name === name);
  if (!processInfo?.pm2_env?.pm_exec_path?.startsWith(`${currentRelease}/`)) {
    throw new Error(`${name} is not running from ${currentRelease}`);
  }
}
NODE
nginx -t
echo "LH-SSO release verification passed for $(cat "$base/current-release")."
