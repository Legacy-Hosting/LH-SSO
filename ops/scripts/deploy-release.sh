#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 || $# -ne 3 ]]; then
  echo "Usage as root: $0 ARCHIVE CHECKSUM VERSION" >&2
  exit 2
fi
archive=$(readlink -f "$1")
checksum=$(readlink -f "$2")
version=$3
if [[ ! -f $archive || ! -f $checksum || ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
  echo "Invalid SSO release archive, checksum, or version" >&2
  exit 1
fi
expected=$(awk 'NR==1 {print $1}' "$checksum")
actual=$(sha256sum "$archive" | awk '{print $1}')
if [[ ! $expected =~ ^[a-f0-9]{64}$ || $expected != "$actual" ]]; then
  echo "SSO release checksum verification failed" >&2
  exit 1
fi

base=/opt/legacy-hosting/sso
release="$base/releases/$version"
environment_file=/etc/legacy-hosting/sso.env
if [[ -e $release ]]; then
  echo "SSO release already exists: $release" >&2
  exit 1
fi
for certificate_file in fullchain.pem privkey.pem; do
  if [[ ! -r /etc/letsencrypt/live/auth.legacyhosting.xyz/$certificate_file ]]; then
    echo "Missing TLS certificate file for auth.legacyhosting.xyz" >&2
    exit 1
  fi
done
install -d -m 0755 "$base/releases"
staging=$(mktemp -d "$base/releases/.staging-${version}.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
tar -xzf "$archive" --no-same-owner --strip-components=1 -C "$staging"
for path in package.json pnpm-lock.yaml ecosystem.config.cjs dist/src/server.js \
  dist/src/oidc-server.js dist/src/database/migrate.js \
  dist/src/migrate-legacy-passkeys.js database/migrations \
  ops/nginx/auth.legacyhosting.xyz.conf ops/scripts/validate-production-env.sh; do
  if [[ ! -e "$staging/$path" ]]; then
    echo "SSO release is missing $path" >&2
    exit 1
  fi
done
"$staging/ops/scripts/validate-production-env.sh" "$environment_file"
ln -s "$environment_file" "$staging/.env"
pnpm --dir "$staging" install --prod --frozen-lockfile
if [[ -x /usr/local/lib/legacy-hosting-ops/backup-mysql.sh && \
      -f /etc/legacy-hosting/backups/sso.env ]]; then
  /usr/local/lib/legacy-hosting-ops/backup-mysql.sh /etc/legacy-hosting/backups/sso.env
else
  echo "A verified SSO backup job is required before migrations" >&2
  exit 1
fi
(cd "$staging" && node dist/src/database/migrate.js)
chown -R root:root "$staging"
chmod 0755 "$staging"
mv "$staging" "$release"
trap - EXIT

previous=
if [[ -L $base/current ]]; then
  previous=$(readlink -f "$base/current" 2>/dev/null || true)
  if [[ -n $previous && $previous == "$base/releases/"* && -d $previous ]]; then
    ln -sfn "$previous" "$base/previous"
  else
    echo "Current SSO symlink points outside the release directory" >&2
    exit 1
  fi
elif [[ -e $base/current ]]; then
  echo "$base/current must be a release symlink" >&2
  exit 1
fi
ln -sfn "$release" "$base/current"

rollback_on_error() {
  pm2 delete lh-sso >/dev/null 2>&1 || true
  pm2 delete lh-sso-oidc >/dev/null 2>&1 || true
  if [[ -n $previous && -d $previous ]]; then
    ln -sfn "$previous" "$base/current"
    pm2 start "$previous/ecosystem.config.cjs" --update-env || true
  else
    rm -f -- "$base/current"
  fi
}
trap rollback_on_error ERR
pm2 delete lh-sso >/dev/null 2>&1 || true
pm2 delete lh-sso-oidc >/dev/null 2>&1 || true
pm2 start "$release/ecosystem.config.cjs" --update-env
pm2 save
curl --fail --silent --show-error --retry 10 --retry-delay 2 --retry-connrefused \
  http://127.0.0.1:8080/health | grep -q '"status":"ok"'
curl --fail --silent --show-error --retry 10 --retry-delay 2 --retry-connrefused \
  http://127.0.0.1:8081/.well-known/openid-configuration | grep -q '"authorization_endpoint"'
install -m 0644 "$release/ops/nginx/auth.legacyhosting.xyz.conf" \
  /etc/nginx/sites-available/auth.legacyhosting.xyz.conf
ln -sfn /etc/nginx/sites-available/auth.legacyhosting.xyz.conf \
  /etc/nginx/sites-enabled/auth.legacyhosting.xyz.conf
nginx -t
systemctl reload nginx
trap - ERR

printf '%s\n' "$version" > "$base/current-release"
echo "LH-SSO $version deployed and verified."
