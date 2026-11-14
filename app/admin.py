import datetime
import secrets

from auth import (
    IdentityError,
    claims_identity,
    hash_token,
    new_token,
    utcnow,
    verify_entra_token,
)
from config import Config
from database import db, init_database
from dev import ensure_dev_account, register_routes as register_dev_routes, validate_config as validate_dev_config
from flask import Flask, current_app, jsonify, request
from models import Credential, User


def create_app():

    app = Flask(__name__)

    app.config.from_object(Config)

    if not app.config["SQLALCHEMY_DATABASE_URI"]:
        raise RuntimeError("DATABASE_URL is required")

    if not app.config["ADMIN_API_KEY"]:
        raise RuntimeError("ADMIN_API_KEY is required")

    # Fail fast on a misconfigured dev account, before touching the database.
    validate_dev_config(app)

    init_database(app)

    def cors_origin():
        """Return the request Origin if it is explicitly allowed."""

        origin = request.headers.get("Origin")

        if not origin:
            return None

        allowed = current_app.config["CORS_ORIGINS"]

        if "*" in allowed or origin in allowed:
            return origin

        return None

    @app.after_request
    def add_cors_headers(response):
        """Let the frontend call the API from an allowlisted origin."""

        origin = cors_origin()

        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Headers"] = (
                "Content-Type, Authorization, X-Admin-Key, X-Dev-Key"
            )
            response.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, DELETE, OPTIONS"
            )
            response.headers.add("Vary", "Origin")

        return response

    def admin_required():

        supplied = request.headers.get("X-Admin-Key", "")
        expected = current_app.config["ADMIN_API_KEY"]

        return secrets.compare_digest(supplied, expected)

    def bearer_token():

        scheme, _, token = request.headers.get("Authorization", "").partition(" ")

        return token.strip() if scheme.lower() == "bearer" else ""

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/enroll", methods=["POST"])
    def enroll():
        """Exchange a silently acquired Entra ID access token for a device
        proxy credential. No user interaction, identity proven by signature."""

        try:
            claims = verify_entra_token(bearer_token(), current_app.config)
            entra_oid, username = claims_identity(claims)

        except IdentityError as exc:
            return jsonify({"error": str(exc)}), 401

        data = request.get_json(silent=True) or {}

        device_id = str(data.get("device_id", "")).strip() or claims.get("deviceid")

        if device_id is not None:
            device_id = str(device_id)[:100] or None

        user = (
            User.query.filter_by(entra_oid=entra_oid).first()
            or User.query.filter_by(username=username).first()
        )

        if user is None:
            if not current_app.config["AUTO_ENROLL"]:
                return jsonify({"error": "User not allowed"}), 403

            user = User(username=username, entra_oid=entra_oid, active=True)
            db.session.add(user)

        if not user.active:
            return jsonify({"error": "User not allowed"}), 403

        # Keep the row aligned with Entra after a UPN rename.
        user.entra_oid = entra_oid
        user.username = username

        token = new_token()

        expires_at = utcnow() + datetime.timedelta(
            days=current_app.config["CREDENTIAL_TTL_DAYS"]
        )

        credential = Credential.query.filter_by(
            user_id=user.id, device_id=device_id
        ).first()

        if credential:
            # Re-enrollment rotates this device's credential only.
            credential.token_hash = hash_token(token)
            credential.expires_at = expires_at
            credential.revoked = False

        else:
            credential = Credential(
                user=user,
                device_id=device_id,
                token_hash=hash_token(token),
                expires_at=expires_at,
            )
            db.session.add(credential)

        db.session.commit()

        # The plaintext credential is returned once; the device stores it in
        # its platform credential store and replays it as Basic auth.
        return jsonify(
            {
                "proxy_host": current_app.config["PROXY_HOST"],
                "proxy_port": current_app.config["PROXY_PORT"],
                "auth_scheme": "Basic",
                "username": user.username,
                "password": token,
                "expires_at": expires_at.isoformat(),
            }
        )

    @app.route("/admin/users", methods=["POST"])
    def create_user():
        """Pre-register an allowed user. Issues no secret: the device gets its
        credential itself through /enroll."""

        if not admin_required():
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json(silent=True) or {}

        username = str(data.get("username", "")).strip().lower()
        entra_oid = str(data.get("entra_oid", "")).strip() or None

        if not username or len(username) > 100:
            return jsonify({"error": "Invalid username"}), 400

        if entra_oid and len(entra_oid) > 64:
            return jsonify({"error": "Invalid entra_oid"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"error": "User already exists"}), 409

        user = User(username=username, entra_oid=entra_oid, active=True)

        db.session.add(user)
        db.session.commit()

        return jsonify(
            {
                "id": user.id,
                "username": user.username,
                "entra_oid": user.entra_oid,
                "active": user.active,
            }
        ), 201

    @app.route("/admin/users", methods=["GET"])
    def list_users():

        if not admin_required():
            return jsonify({"error": "Unauthorized"}), 401

        users = User.query.order_by(User.id).all()

        return jsonify(
            [
                {
                    "id": u.id,
                    "username": u.username,
                    "entra_oid": u.entra_oid,
                    "active": u.active,
                    "created_at": u.created_at.isoformat(),
                    "last_used": (u.last_used.isoformat() if u.last_used else None),
                    "devices": [
                        {
                            "id": c.id,
                            "device_id": c.device_id,
                            "expires_at": c.expires_at.isoformat(),
                            "revoked": c.revoked,
                            "last_used": (
                                c.last_used.isoformat() if c.last_used else None
                            ),
                        }
                        for c in u.credentials
                    ],
                }
                for u in users
            ]
        )

    @app.route("/admin/users/<int:user_id>", methods=["DELETE"])
    def revoke_user(user_id):

        if not admin_required():
            return jsonify({"error": "Unauthorized"}), 401

        user = db.session.get(User, user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        user.active = False

        for credential in user.credentials:
            credential.revoked = True

        db.session.commit()

        return jsonify({"message": "User disabled", "user_id": user.id})

    @app.route("/admin/credentials/<int:credential_id>", methods=["DELETE"])
    def revoke_credential(credential_id):
        """Revoke a single device without locking the user out elsewhere."""

        if not admin_required():
            return jsonify({"error": "Unauthorized"}), 401

        credential = db.session.get(Credential, credential_id)

        if not credential:
            return jsonify({"error": "Credential not found"}), 404

        credential.revoked = True
        db.session.commit()

        return jsonify({"message": "Credential revoked", "credential_id": credential.id})

    if app.config["DEV_MODE"]:
        ensure_dev_account(app)

    register_dev_routes(app)

    return app
