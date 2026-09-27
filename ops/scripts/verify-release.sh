#!/usr/bin/env bash
set -Eeuo pipefail

base=/opt/legacy-hosting/sso
test -L "$base/current"
test -f "$base/current-release"
curl --fail --silent --show-error http://127.0.0.1:8080/health | \
  grep -q '"database":"connected"'
pm2 describe lh-sso >/dev/null
current_release=$(readlink -f "$base/current")
CURRENT_RELEASE="$current_release" node <<'NODE'
const { execFileSync } = require("node:child_process");
const currentRelease = process.env.CURRENT_RELEASE;
const processInfo = JSON.parse(execFileSync("pm2", ["jlist"], { encoding: "utf8" }))
  .find((item) => item.name === "lh-sso");
if (!processInfo?.pm2_env?.pm_exec_path?.startsWith(`${currentRelease}/`)) {
  throw new Error(`lh-sso is not running from ${currentRelease}`);
}
NODE
nginx -t
echo "LH-SSO release verification passed for $(cat "$base/current-release")."
