"""Identity verification and proxy credential handling.

Two distinct secrets, do not confuse them:

1. Entra ID access token (JWT, short lived) - proves *who* the caller is.
   Obtained silently on the device by the enrollment agent (MSAL silent /
   integrated Windows auth / managed identity). Never stored by us.

2. Proxy credential (opaque random string, long lived) - what the OS proxy
   stack replays on every request as RFC 7617 Basic auth. Stored hashed here,
   stored in the platform credential store on the device.
"""

import datetime
import hashlib
import hmac
import secrets

import jwt
from jwt import PyJWKClient

TOKEN_BYTES = 32

_jwks_clients: dict[str, PyJWKClient] = {}


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class IdentityError(Exception):
    """Raised when an Entra ID access token cannot be trusted."""


def _jwks_client(tenant_id: str) -> PyJWKClient:
    client = _jwks_clients.get(tenant_id)

    if client is None:
        client = PyJWKClient(
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
            cache_keys=True,
        )
        _jwks_clients[tenant_id] = client

    return client


def verify_entra_token(access_token: str, config) -> dict:
    """Validate an Entra ID v2.0 access token, return its claims.

    Signature, issuer, audience and expiry are all checked. Anything less
    would let a caller impersonate any user, which defeats attribution.
    """

    if not access_token:
        raise IdentityError("Missing access token")

    tenant_id = config.get("ENTRA_TENANT_ID")
    audience = config.get("ENTRA_AUDIENCE")

    if not tenant_id or not audience:
        raise IdentityError("Entra ID verification is not configured")

    try:
        key = _jwks_client(tenant_id).get_signing_key_from_jwt(access_token).key

        claims = jwt.decode(
            access_token,
            key,
            algorithms=["RS256"],
            audience=audience,
            issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            options={"require": ["exp", "iss", "aud", "sub"]},
        )

    except Exception as exc:  # reason stays opaque to the caller on purpose
        raise IdentityError("Invalid access token") from exc

    if claims.get("tid") != tenant_id:
        raise IdentityError("Token from an unexpected tenant")

    return claims


def claims_identity(claims: dict) -> tuple[str, str]:
    """Return (object_id, username) for an Entra ID token."""

    object_id = claims.get("oid") or claims.get("sub")

    username = (
        claims.get("preferred_username") or claims.get("upn") or claims.get("email")
    )

    if not object_id or not username:
        raise IdentityError("Token lacks identity claims")

    return str(object_id), str(username).strip().lower()
