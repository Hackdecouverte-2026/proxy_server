import os


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-in-production")

    DEBUG = False

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
        "pool_size": 10,
        "max_overflow": 20,
    }

    # Administration
    ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

    # Entra ID (silent device enrollment)
    ENTRA_TENANT_ID = os.environ.get("ENTRA_TENANT_ID")
    ENTRA_AUDIENCE = os.environ.get("ENTRA_AUDIENCE")

    # Auto-create a user row on first successful Entra sign-in instead of
    # requiring an admin to pre-register it.
    AUTO_ENROLL = os.environ.get("AUTO_ENROLL", "false").lower() == "true"

    # Development account. When DEV_MODE=true a single always-active user with a
    # fixed credential is seeded so the enroll -> proxy flow can run without
    # Entra ID. Fail-closed: DEV_MODE refuses to start without an explicit
    # DEV_PASSWORD, and nothing here is reachable while DEV_MODE=false.
    DEV_MODE = os.environ.get("DEV_MODE", "false").lower() == "true"
    DEV_USERNAME = os.environ.get("DEV_USERNAME", "dev@localhost").strip().lower()
    DEV_PASSWORD = os.environ.get("DEV_PASSWORD")

    # Lifetime of a device proxy credential, in days.
    CREDENTIAL_TTL_DAYS = int(os.environ.get("CREDENTIAL_TTL_DAYS", "90"))

    # Proxy
    PROXY_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
    PROXY_PORT = int(os.environ.get("PROXY_PORT", "8888"))
    PROXY_REALM = os.environ.get("PROXY_REALM", "proxy")

    # Request limits
    MAX_REQUEST_SIZE = int(os.environ.get("MAX_REQUEST_SIZE", "10485760"))

    # Browser origins allowed to call the API (the frontend). Empty = no CORS.
    CORS_ORIGINS = {
        origin.strip()
        for origin in os.environ.get("CORS_ORIGINS", "").split(",")
        if origin.strip()
    }

    # Allowed destinations
    ALLOWED_HOSTS = {
        host.strip().lower()
        for host in os.environ.get("ALLOWED_HOSTS", "").split(",")
        if host.strip()
    }
