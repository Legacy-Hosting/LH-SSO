# Legacy Hosting SSO

Central identity authority for Legacy Hosting services. This repository owns the isolated SSO database, an OpenID Connect authorization server, health endpoint, and authenticated Discord staff-role synchronization contract.

`LH-SSO` is the final source of truth for staff authorization. Discord supplies role assignments by immutable role ID, but Discord roles are not trusted directly by Hub, Panel, API, or Status.

Use a separate `legacyhosting_sso` database on the existing Managed MySQL cluster. Only the API and SSO Droplets should be trusted database sources; the public Panel, Hub, Status, and Discord processes must use service APIs instead of direct database connections.

The OIDC server supports only Authorization Code Flow, requires PKCE for every client, uses short-lived signed access/ID tokens, rotates refresh tokens, and persists protocol state in MySQL. Clients and resource audiences are statically allowlisted; dynamic registration is disabled. Signing keys are loaded from a protected private JWKS file and the first key is active. Prepend a new key while retaining prior public keys during rotation.

RP-initiated logout is enabled for browser sign-out. Each confidential client has an allowlisted post-logout redirect and HTTPS back-channel logout URI. SSO signs logout tokens with the same ES256 key set so API and Hub can validate the issuer, audience, event, age, and subject before revoking their own sessions.

The confidential `lh-panel` client redirects to the LH-API callback, not to the static Panel bundle. API performs the code exchange and ID-token validation server-side, then creates a normal HttpOnly Panel session and redirects the browser back to Panel.

The existing Panel login remains authoritative during the migration window. When OIDC requests authentication, SSO redirects the browser to `OIDC_LEGACY_LOGIN_URL` with `sso_interaction` and `sso_completion_uri`. After authenticating the current user, the trusted Panel backend must:

1. POST the user's SSO `subject` and `interactionUid` to `/internal/oidc/login-tickets` using `LH_IDENTITY_BRIDGE_TOKEN`.
2. Render an auto-submitting HTML form that POSTs the returned one-time `ticket` to `completionUri`.
3. Never expose `LH_IDENTITY_BRIDGE_TOKEN` to the browser.

Tickets expire after 60 seconds, are bound to one interaction, and can be consumed once. On the first successful bridge request, SSO provisions a `legacy_panel` identity whose immutable subject equals the existing API user UUID. A matching email attached to another SSO subject is rejected instead of being merged automatically. The bridge endpoint is restricted to the AMS3 VPC by Nginx. Remove this bridge after passkeys and account recovery have moved to SSO.

## Passkey cutover

`OIDC_LOGIN_MODE=legacy_bridge` keeps the existing Panel passkey flow as the rollback-safe default. `OIDC_LOGIN_MODE=passkey` serves the SSO-owned, same-origin passkey screen and verifies migrated credentials directly in the SSO database. Do not enable passkey mode until the dry-run and applied migration report the expected user and credential counts.

The source and target WebAuthn RP IDs must match exactly; credentials cannot be moved to a different RP ID. Configure the temporary `LEGACY_DATABASE_*` values, keep both databases inside the trusted AMS3 VPC, then run:

```bash
pnpm build
pnpm passkeys:migrate-legacy
pnpm passkeys:migrate-legacy --apply
```

The first command performs all collision and binding checks inside a transaction and rolls it back. The applied migration is idempotent, preserves credential IDs, public keys, counters and metadata, and refuses email, identity or credential collisions. Remove the legacy database credentials from `sso.env` after the cutover has been verified. Switching `OIDC_LOGIN_MODE` back to `legacy_bridge` is the authentication rollback; it does not delete migrated credentials.

Generate an initial two-key ES256 set directly on the SSO server:

```bash
install -d -m 0700 /etc/legacy-hosting
pnpm oidc:generate-keys /etc/legacy-hosting/sso-oidc-jwks.json
```

Rotate by prepending a new active key while retaining verification keys:

```bash
pnpm oidc:generate-keys /etc/legacy-hosting/sso-oidc-jwks.json --rotate
```

The public issuer is `https://auth.legacyhosting.xyz`. Fastify serves health, interactions, and authenticated internal endpoints on localhost port 8080. The OIDC protocol server listens on localhost port 8081. Nginx routes both behind the one issuer origin.

## Releases

Tags named `v*` publish immutable archives to `LH-Releases/LH-SSO` and checksums to its `SHA256` directory. The archive owns the SSO Nginx, environment validation, deploy, rollback, and verification scripts. Deploy on `ams3-sso-01` with:

```bash
ops/scripts/deploy-release.sh ARCHIVE CHECKSUM VERSION
```

The deployment requires the protected `/etc/legacy-hosting/sso.env`, the `LH-Ops` encrypted backup tooling, and `/etc/legacy-hosting/backups/sso.env` before it will run migrations.
