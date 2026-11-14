import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    # Entra ID userPrincipalName, lowercased. This is the Basic auth username
    # the device sends, so every proxied request is attributable.
    username = db.Column(db.String(100), unique=True, nullable=False)

    # Entra ID object id (immutable, survives UPN renames).
    entra_oid = db.Column(db.String(64), unique=True, nullable=True)

    active = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(db.DateTime, default=_utcnow)

    last_used = db.Column(db.DateTime, nullable=True)

    credentials = db.relationship(
        "Credential", back_populates="user", cascade="all, delete-orphan"
    )


class Credential(db.Model):
    """One proxy credential per enrolled device, so a lost device is revoked
    alone and rotation never logs out the other devices of the same user."""

    __tablename__ = "credentials"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    device_id = db.Column(db.String(100), nullable=True)

    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)

    created_at = db.Column(db.DateTime, default=_utcnow)

    expires_at = db.Column(db.DateTime, nullable=False)

    last_used = db.Column(db.DateTime, nullable=True)

    revoked = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship("User", back_populates="credentials")

    __table_args__ = (
        db.UniqueConstraint("user_id", "device_id", name="uq_credential_user_device"),
    )

    def usable(self, now):
        expires_at = self.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)

        return not self.revoked and expires_at > now


class AccessLog(db.Model):
    __tablename__ = "access_logs"

    id = db.Column(
        db.BigInteger().with_variant(db.Integer, "sqlite"), primary_key=True
    )

    # NULL when the caller could not be authenticated.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    credential_id = db.Column(
        db.Integer, db.ForeignKey("credentials.id"), nullable=True
    )

    # Set on rejected requests: auth_failed, not_allowed, port_not_allowed,
    # non_public.
    reason = db.Column(db.String(50), nullable=True)

    method = db.Column(db.String(20))
    hostname = db.Column(db.String(255))
    status = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=_utcnow)
