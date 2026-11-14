"""Development account: run the enroll -> proxy flow without Entra ID.

Everything in this module is inert unless ``DEV_MODE=true``. It exists so the
frontend and the on-device agent can be wired up and smoke-tested against a
real proxy credential while the tenant / MSAL side is not available yet.

The seeded credential is the same shape as a production one: opaque password,
stored SHA-256 hashed, replayed as RFC 7617 Basic. The only difference is that
its password comes from ``DEV_PASSWORD`` and it never expires, so the dev
credential is predictable by design and must never be enabled outside a
throwaway environment.
"""

import datetime
import secrets

from auth import hash_token, utcnow
from flask import current_app, jsonify, request
from models import AccessLog, Credential, db, User

DEV_DEVICE_ID = "dev"


def validate_config(app):
    """Fail closed: a dev account needs an explicit, non-trivial password."""

    if not app.config["DEV_MODE"]:
        return

    password = app.config["DEV_PASSWORD"]

    if not password or len(password) < 12:
        raise RuntimeError(
            "DEV_MODE requires DEV_PASSWORD of at least 12 characters"
        )

    if not app.config["DEV_USERNAME"]:
        raise RuntimeError("DEV_MODE requires DEV_USERNAME")


def ensure_dev_account(app):
    """Create/refresh the dev user and its fixed credential. Idempotent."""

    username = app.config["DEV_USERNAME"]
    token_hash = hash_token(app.config["DEV_PASSWORD"])
    expires_at = utcnow() + datetime.timedelta(
        days=app.config["CREDENTIAL_TTL_DAYS"]
    )

    with app.app_context():
        user = User.query.filter_by(username=username).first()

        if user is None:
            user = User(username=username, active=True)
            db.session.add(user)
            db.session.flush()

        user.active = True

        credential = Credential.query.filter_by(
            user_id=user.id, device_id=DEV_DEVICE_ID
        ).first()

        if credential is None:
            credential = Credential(
                user=user,
                device_id=DEV_DEVICE_ID,
                token_hash=token_hash,
                expires_at=expires_at,
            )
            db.session.add(credential)
        else:
            credential.token_hash = token_hash
            credential.revoked = False
            credential.expires_at = expires_at

        db.session.commit()

        app.logger.warning(
            "DEV_MODE active: username=%r credential password from DEV_PASSWORD",
            username,
        )


def register_routes(app):
    """Expose ``POST /dev/enroll`` while ``DEV_MODE`` is on."""

    if not app.config["DEV_MODE"]:
        return

    @app.route("/dev/enroll", methods=["POST"])
    def dev_enroll():
        """Return the seeded dev credential. Gated by the dev password itself.

        Same response shape as ``/enroll`` so a client can point at either
        endpoint and switch back to Entra without code changes.
        """

        supplied = request.headers.get("X-Dev-Key", "")

        if not secrets.compare_digest(supplied, app.config["DEV_PASSWORD"]):
            return jsonify({"error": "Unauthorized"}), 401

        user = User.query.filter_by(
            username=app.config["DEV_USERNAME"]
        ).first()

        credential = (
            Credential.query.filter_by(
                user_id=user.id, device_id=DEV_DEVICE_ID
            ).first()
            if user
            else None
        )

        if user is None or credential is None or not user.active:
            return jsonify({"error": "Dev account not provisioned"}), 500

        return jsonify(
            {
                "proxy_host": app.config["PROXY_HOST"],
                "proxy_port": app.config["PROXY_PORT"],
                "auth_scheme": "Basic",
                "username": user.username,
                "password": app.config["DEV_PASSWORD"],
                "expires_at": credential.expires_at.isoformat(),
            }
        )

    @app.route("/dev/logs", methods=["GET"])
    def dev_logs():
        """All access logs, newest first. Gated by the dev key.

        Includes rejected requests (``reason`` set, ``username`` null when
        unauthenticated). Query: ``limit`` (default 100, max 1000), ``before_id`` for paging.
        """

        supplied = request.headers.get("X-Dev-Key", "")

        if not secrets.compare_digest(supplied, app.config["DEV_PASSWORD"]):
            return jsonify({"error": "Unauthorized"}), 401

        limit = min(max(request.args.get("limit", 100, type=int), 1), 1000)
        before_id = request.args.get("before_id", type=int)

        query = db.session.query(AccessLog, User.username).outerjoin(
            User, User.id == AccessLog.user_id
        )

        if before_id:
            query = query.filter(AccessLog.id < before_id)

        rows = query.order_by(AccessLog.id.desc()).limit(limit).all()

        return jsonify(
            [
                {
                    "id": log.id,
                    "username": username,
                    "credential_id": log.credential_id,
                    "method": log.method,
                    "hostname": log.hostname,
                    "status": log.status,
                    "reason": log.reason,
                    "created_at": log.created_at.isoformat(),
                }
                for log, username in rows
            ]
        )
