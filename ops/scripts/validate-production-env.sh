#!/usr/bin/env bash
set -Eeuo pipefail

environment_file=${1:-/etc/legacy-hosting/sso.env}
if [[ ! -f $environment_file ]]; then
  echo "Missing protected SSO environment: $environment_file" >&2
  exit 1
fi
permissions=$(stat -c '%a' "$environment_file")
if (( 10#$permissions > 600 )); then
  echo "$environment_file must have mode 0600 or stricter" >&2
  exit 1
fi
set -a
. "$environment_file"
set +a
required=(NODE_ENV HOST PORT DATABASE_URL DATABASE_SSL_CA LH_DISCORD_INTERNAL_TOKEN)
for name in "${required[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "Missing SSO setting: $name" >&2
    exit 1
  fi
done
if [[ $NODE_ENV != production || $HOST != 127.0.0.1 ]]; then
  echo "SSO must run in production mode on 127.0.0.1" >&2
  exit 1
fi
if [[ ! $PORT =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo "Invalid SSO port" >&2
  exit 1
fi
if [[ ! -r $DATABASE_SSL_CA ]]; then
  echo "Cannot read the SSO database CA certificate" >&2
  exit 1
fi
if [[ ${#LH_DISCORD_INTERNAL_TOKEN} -lt 32 ]]; then
  echo "LH_DISCORD_INTERNAL_TOKEN must contain at least 32 characters" >&2
  exit 1
fi

echo "SSO production environment validation passed without printing secrets."
