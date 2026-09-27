# Legacy Hosting SSO

Central identity authority for Legacy Hosting services. This repository currently establishes the isolated SSO database, health endpoint, and authenticated Discord staff-role synchronization contract.

`LH-SSO` is the final source of truth for staff authorization. Discord supplies role assignments by immutable role ID, but Discord roles are not trusted directly by Hub, Panel, API, or Status.

Use a separate `legacyhosting_sso` database on the existing Managed MySQL cluster. Only the API and SSO Droplets should be trusted database sources; the public Panel, Hub, Status, and Discord processes must use service APIs instead of direct database connections.

The public OIDC authorization-code flow with PKCE, passkeys, client registration, key rotation, and migration of existing Panel sessions is the next identity phase. Until that phase is completed and tested, the existing Panel login remains authoritative and must not be removed.
