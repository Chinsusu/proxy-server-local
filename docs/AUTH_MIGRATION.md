# Authentication migration

PGW v2 removes the environment-based JWT secret and the validation bypass.
Before starting `pgw-api`, create a random signing key with at least 32 bytes
at `/etc/pgw/jwt_secret`, owned by the API service account and mode `0600`,
then configure the included service unit:

```ini
LoadCredential=jwt_secret:/etc/pgw/jwt_secret
LoadCredential=agent_service_token:/etc/pgw/agent.token
LoadCredential=admin_pass_hash:/etc/pgw/admin_pass_hash
Environment=PGW_API_ADDR=127.0.0.1:8080
```

`CREDENTIALS_DIRECTORY/jwt_secret` is preferred at runtime. If systemd
credentials are unavailable, `PGW_JWT_SECRET_FILE` may name an absolute,
owner-only `0600` fallback file. `PGW_JWT_SECRET` and `PGW_JWT_STRICT` cause
startup to fail, even when empty.

The browser contract also changes: `POST /v1/auth/login` returns `204 No
Content` and one `pgw_jwt` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`,
`Path=/`, a 12-hour `Max-Age`, and `Expires`. It never returns a JWT in JSON.
The API must remain on numeric loopback; terminate TLS at the UI reverse proxy.

Scripts that obtained a token from the login response must migrate to an
operator-managed service-auth flow. Existing bearer validation remains only
during the API migration window; no login endpoint exposes a new bearer token.

Admin bootstrap no longer accepts `PGW_ADMIN_PASS` or `PGW_ADMIN_PASS_HASH`.
Use `pgw-api hash-admin-password` with password bytes on bounded stdin to
create `/etc/pgw/admin_pass_hash`, mode `0600`. For first install, provision the
password only at the fixed root-owned path
`/etc/pgw/credential-inbox/admin_password` (mode `0400`/`0600`). Caller-selected
`PGW_ADMIN_PASS_FILE` is rejected. `pgw-api` opens the fixed file once through
`openat` dirfds with `O_NOFOLLOW`, hashes that same descriptor, and the installer
removes the one-use input. Only `pgw-api` receives the resulting PHC credential.
