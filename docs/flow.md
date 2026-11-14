# Flow

## Overview

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant Dev as Device agent
    participant Entra as Entra ID
    participant API as Flask API (/enroll, /admin)
    participant DB as MySQL
    participant Proxy as Proxy :8888
    participant Dst as Allowed destination

    rect rgb(240,240,255)
    note over Admin,DB: 1. Provisioning
    Admin->>API: POST /admin/users {username, entra_oid?}<br/>X-Admin-Key
    API->>DB: insert User(active)
    API-->>Admin: 201 {id, username, ...}
    note right of API: skipped if AUTO_ENROLL=true
    end

    rect rgb(240,255,240)
    note over Dev,DB: 2. Enrollment (every ≤90 days)
    Dev->>Entra: silent token request (MSAL / IWA)
    Entra-->>Dev: access token (JWT)
    Dev->>API: POST /enroll {device_id}<br/>Authorization: Bearer JWT
    API->>Entra: fetch JWKS (cached)
    API->>API: verify sig, iss, aud, exp, tid<br/>extract oid + UPN
    API->>DB: find user by oid, else username
    alt unknown user and AUTO_ENROLL off, or inactive
        API-->>Dev: 403
    else allowed
        API->>DB: upsert Credential(user, device_id)<br/>store SHA-256(token)
        API-->>Dev: {proxy_host, proxy_port, username,<br/>password=token (once), expires_at}
        Dev->>Dev: store in OS credential store,<br/>set system proxy
    end
    end

    rect rgb(255,248,235)
    note over Dev,Dst: 3. Proxied request
    Dev->>Proxy: CONNECT host:443 / GET http://host/...
    alt no Proxy-Authorization
        Proxy-->>Dev: 407 Proxy-Authenticate: Basic
        Dev->>Proxy: retry with Basic base64(upn:token)
    end
    Proxy->>DB: hash token, load Credential + User
    Proxy->>Proxy: usable? user active? upn matches?
    Proxy->>Proxy: host in ALLOWED_HOSTS, port 80/443,<br/>all resolved IPs global
    alt rejected
        Proxy-->>Dev: 407 / 502
    else accepted
        Proxy->>Dst: open TCP tunnel / forward HTTP
        Dst-->>Proxy: response bytes
        Proxy-->>Dev: relay
        Proxy->>DB: AccessLog + last_used (user, credential)
    end
    end
```

## Revocation

```mermaid
flowchart LR
    A[Admin] -->|DELETE /admin/users/id| U[user.active = false<br/>all credentials revoked]
    A -->|DELETE /admin/credentials/id| C[one credential revoked]
    U --> P[Proxy auth fails → 407]
    C --> P
    P --> R[Device re-enrolls via /enroll<br/>fails 403 if user inactive]
```

## Services (docker-compose)

- **db**: MySQL 8.4.
- **api**: gunicorn, `admin:create_app()`, bound to `127.0.0.1:8000`.
- **proxy**: `python proxy.py`, threaded forward proxy on `:8888`. Shares the Flask app and DB. Origin-form requests (e.g. `POST /enroll`) are served by Flask via `serve_local`.

## Known gaps

- `ALLOWED_HOSTS` read twice: `proxy.py` from env directly, ignoring `Config.ALLOWED_HOSTS`.
- `PUT`/`DELETE`/etc. always go through `forward_http`, so they get 407 when sent to local routes.
- `CONNECT` logs status 200 even if the tunnel fails after the handshake.
- `/enroll` and admin routes over the proxy port are plain HTTP unless TLS is terminated in front.
