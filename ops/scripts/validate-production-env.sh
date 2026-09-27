#!/usr/bin/env bash
set -Eeuo pipefail

environment_file=${1:-/etc/legacy-hosting/sso.env}
if [[ ! -f $environment_file ]]; then
  echo "Missing protected SSO environment: $environment_file" >&2
  exit 1
fi
permissions=$(stat -c '%a' "$environment_file")
if (( (8#$permissions & 077) != 0 )); then
  echo "$environment_file must have mode 0600 or stricter" >&2
  exit 1
fi
set -a
. "$environment_file"
set +a
required=(NODE_ENV HOST PORT OIDC_PORT DATABASE_URL DATABASE_SSL_CA LH_DISCORD_INTERNAL_TOKEN \
  LH_IDENTITY_BRIDGE_TOKEN OIDC_ISSUER OIDC_COOKIE_KEYS_JSON OIDC_JWKS_FILE \
  OIDC_CLIENTS_JSON OIDC_RESOURCES_JSON OIDC_LEGACY_LOGIN_URL OIDC_LOGIN_MODE \
  WEBAUTHN_RP_NAME WEBAUTHN_RP_ID WEBAUTHN_ORIGIN)
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
if [[ $OIDC_LOGIN_MODE != legacy_bridge && $OIDC_LOGIN_MODE != passkey ]]; then
  echo "OIDC_LOGIN_MODE must be legacy_bridge or passkey" >&2
  exit 1
fi
if [[ $WEBAUTHN_ORIGIN != https://* ]]; then
  echo "WEBAUTHN_ORIGIN must use HTTPS" >&2
  exit 1
fi
webauthn_host=${WEBAUTHN_ORIGIN#https://}
webauthn_host=${webauthn_host%%/*}
webauthn_host=${webauthn_host%%:*}
if [[ $webauthn_host != "$WEBAUTHN_RP_ID" && $webauthn_host != *."$WEBAUTHN_RP_ID" ]]; then
  echo "WEBAUTHN_RP_ID must be the WebAuthn origin host or a parent domain" >&2
  exit 1
fi
if [[ ! $PORT =~ ^[0-9]+$ || ! $OIDC_PORT =~ ^[0-9]+$ ]] || \
   (( PORT < 1 || PORT > 65535 || OIDC_PORT < 1 || OIDC_PORT > 65535 || PORT == OIDC_PORT )); then
  echo "Invalid or conflicting SSO ports" >&2
  exit 1
fi
if [[ ! -r $DATABASE_SSL_CA ]]; then
  echo "Cannot read the SSO database CA certificate" >&2
  exit 1
fi
legacy_values=0
for name in LEGACY_DATABASE_URL LEGACY_DATABASE_SSL_CA LEGACY_WEBAUTHN_RP_ID; do
  if [[ -n ${!name:-} ]]; then
    ((legacy_values += 1))
  fi
done
if (( legacy_values != 0 && legacy_values != 3 )); then
  echo "All LEGACY_DATABASE_URL, LEGACY_DATABASE_SSL_CA, and LEGACY_WEBAUTHN_RP_ID values must be set together" >&2
  exit 1
fi
if (( legacy_values == 3 )) && [[ ! -r $LEGACY_DATABASE_SSL_CA ]]; then
  echo "Cannot read the legacy database CA certificate" >&2
  exit 1
fi
if [[ ${#LH_DISCORD_INTERNAL_TOKEN} -lt 32 ]]; then
  echo "LH_DISCORD_INTERNAL_TOKEN must contain at least 32 characters" >&2
  exit 1
fi
if [[ ${#LH_IDENTITY_BRIDGE_TOKEN} -lt 32 || $LH_IDENTITY_BRIDGE_TOKEN == "$LH_DISCORD_INTERNAL_TOKEN" ]]; then
  echo "LH_IDENTITY_BRIDGE_TOKEN must be a distinct secret with at least 32 characters" >&2
  exit 1
fi
if [[ ! -r $OIDC_JWKS_FILE ]]; then
  echo "OIDC_JWKS_FILE must be readable and have mode 0600 or stricter" >&2
  exit 1
fi
jwks_permissions=$(stat -c '%a' "$OIDC_JWKS_FILE")
if (( (8#$jwks_permissions & 077) != 0 )); then
  echo "OIDC_JWKS_FILE must be readable and have mode 0600 or stricter" >&2
  exit 1
fi
node - "$OIDC_COOKIE_KEYS_JSON" "$OIDC_CLIENTS_JSON" "$OIDC_RESOURCES_JSON" "$OIDC_JWKS_FILE" <<'NODE'
const fs = require('node:fs');
const [cookiesRaw, clientsRaw, resourcesRaw, jwksFile] = process.argv.slice(2);
const cookies = JSON.parse(cookiesRaw);
const clients = JSON.parse(clientsRaw);
const resources = JSON.parse(resourcesRaw);
const jwks = JSON.parse(fs.readFileSync(jwksFile, 'utf8'));
if (!Array.isArray(cookies) || cookies.length < 2 || cookies.some((key) => typeof key !== 'string' || key.length < 32)) throw new Error('invalid OIDC cookie keys');
if (!Array.isArray(clients) || clients.length === 0) throw new Error('no OIDC clients configured');
if (!Array.isArray(resources) || resources.length === 0) throw new Error('no OIDC resources configured');
if (!Array.isArray(jwks.keys) || jwks.keys.length === 0 || jwks.keys.some((key) => !key.kid || !key.d)) throw new Error('OIDC JWKS must contain private signing keys');
NODE

echo "SSO production environment validation passed without printing secrets."
