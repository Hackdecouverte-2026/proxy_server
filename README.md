# Proxy server

Allowlisting forward proxy (HTTP + CONNECT) with per-user attribution.

## Auth model

Two secrets, never mixed:

| | Entra ID access token | Proxy credential |
|---|---|---|
| Format | JWT, signed by the tenant | opaque random string |
| Lifetime | minutes | `CREDENTIAL_TTL_DAYS` (default 90) |
| Proves | who the user is | that this device was enrolled by that user |
| Stored server-side | never | SHA-256 hash only |
| Sent on | `POST /enroll` as `Authorization: Bearer` | every proxied request as `Proxy-Authorization: Basic` |

Everything is standard: RFC 7235 (`407` + `Proxy-Authenticate`), RFC 7617
(Basic), OAuth 2.0 / OIDC for identity. No bespoke header, no bespoke scheme —
so Windows/macOS proxy stacks, curl, Chromium and Firefox all speak it as is.

### Why Basic and not Bearer

The OS proxy stack and browsers only know Basic/Digest/NTLM/Negotiate for
`Proxy-Authorization`. Basic with
`base64(userPrincipalName:credential)` keeps the identity *in the request*, so
every tunnel line in `access_logs` is attributable to a named user even after
a credential rotation. Bearer-only tokens are no longer accepted.

### Silence

No prompt is ever shown *provided the device is enrolled*: the credential sits
in the platform credential store (Windows Credential Manager / macOS keychain /
`gsettings` or `/etc/environment` on Linux) and is replayed automatically. The
`407` challenge stays (RFC requires it, clients need it to replay
preemptively); a non-enrolled device gets a prompt, which is the intended
failure signal.

## Device enrollment (to implement on the device side)

1. Agent acquires an Entra ID access token **silently**: MSAL
   `AcquireTokenSilent`, Integrated Windows Auth, or the device's managed
   identity. Scope = `api://<proxy-app-id>/.default`. No user interaction.
2. `POST /enroll` with `Authorization: Bearer <access token>` and body
   `{"device_id": "<stable device id>"}`.
3. Response:

   ```json
   {
     "proxy_host": "0.0.0.0", "proxy_port": 8888,
     "auth_scheme": "Basic",
     "username": "alice@corp.com",
     "password": "<credential, shown once>",
     "expires_at": "2026-02-12T19:49:30+00:00"
   }
   ```

4. Agent writes the credential into the OS credential store and points the
   system proxy at `proxy_host:proxy_port`.
5. Re-run before `expires_at` to rotate. Re-enrolling the same `device_id`
   rotates that device only; other devices of the same user keep working.

Until that agent exists, the same flow works by hand with `curl` and
`curl -x http://proxy:8888 --proxy-user 'alice@corp.com:<credential>'`.

## Admin API (`X-Admin-Key`)

- `POST /admin/users` `{username, entra_oid?}` — allowlist a user. Issues no
  secret.
- `GET /admin/users` — users plus their enrolled devices.
- `DELETE /admin/users/<id>` — deactivate user, revoke all its credentials.
- `DELETE /admin/credentials/<id>` — revoke one device.

Set `AUTO_ENROLL=true` to create the user row on first successful Entra
sign-in instead of pre-registering.

## Config

See `.env.example`. `ENTRA_TENANT_ID` and `ENTRA_AUDIENCE` are mandatory for
`/enroll`: signature, issuer, audience, expiry and tenant are all verified,
otherwise anyone could claim any identity.

## Dev account (no Entra ID)

Set in `.env`: `DEV_MODE=true`, `DEV_PASSWORD` (>= 12 chars), optional
`DEV_USERNAME` (default `dev@localhost`), and `CORS_ORIGINS` for the frontend.
On start a dev user + fixed credential (password = `DEV_PASSWORD`) is seeded.

```sh
curl -X POST http://localhost:8000/dev/enroll -H "X-Dev-Key: $DEV_PASSWORD"
curl -x http://localhost:8888 --proxy-user "dev@localhost:$DEV_PASSWORD" http://example.com
```

`/dev/enroll` returns the same shape as `/enroll`, so clients switch by URL
only. With `DEV_MODE=false` the route does not exist (404). Never enable in
production: the credential is static and known.
