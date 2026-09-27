# Legacy Hosting SSO

Central identity authority for Legacy Hosting services. This repository currently establishes the isolated SSO database, health endpoint, and authenticated Discord staff-role synchronization contract.

`LH-SSO` is the final source of truth for staff authorization. Discord supplies role assignments by immutable role ID, but Discord roles are not trusted directly by Hub, Panel, API, or Status.

Use a separate `legacyhosting_sso` database on the existing Managed MySQL cluster. Only the API and SSO Droplets should be trusted database sources; the public Panel, Hub, Status, and Discord processes must use service APIs instead of direct database connections.

The public OIDC authorization-code flow with PKCE, passkeys, client registration, key rotation, and migration of existing Panel sessions is the next identity phase. Until that phase is completed and tested, the existing Panel login remains authoritative and must not be removed.

## Releases

Tags named `v*` publish immutable archives to `LH-Releases/LH-SSO` and checksums to its `SHA256` directory. The archive owns the SSO Nginx, environment validation, deploy, rollback, and verification scripts. Deploy on `ams3-sso-01` with:

```bash
ops/scripts/deploy-release.sh ARCHIVE CHECKSUM VERSION
```

The deployment requires the protected `/etc/legacy-hosting/sso.env`, the `LH-Ops` encrypted backup tooling, and `/etc/legacy-hosting/backups/sso.env` before it will run migrations.
