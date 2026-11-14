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

    # Proxy
    PROXY_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
    PROXY_PORT = int(os.environ.get("PROXY_PORT", "8888"))

    # Request limits
    MAX_REQUEST_SIZE = int(os.environ.get("MAX_REQUEST_SIZE", "10485760"))

    # Allowed destinations
    ALLOWED_HOSTS = {
        host.strip().lower()
        for host in os.environ.get("ALLOWED_HOSTS", "").split(",")
        if host.strip()
    }
