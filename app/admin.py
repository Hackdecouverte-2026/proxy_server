import hashlib
import os
import secrets

from config import Config
from database import db, init_database
from flask import Flask, current_app, jsonify, request
from models import AccessLog, User
from sqlalchemy import select


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_app():

    app = Flask(__name__)

    app.config.from_object(Config)

    if not app.config["SQLALCHEMY_DATABASE_URI"]:
        raise RuntimeError("DATABASE_URL is required")

    if not app.config["ADMIN_API_KEY"]:
        raise RuntimeError("ADMIN_API_KEY is required")

    init_database(app)

    def admin_required():

        supplied = request.headers.get("X-Admin-Key", "")
        expected = current_app.config["ADMIN_API_KEY"]

        return secrets.compare_digest(supplied, expected)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/admin/users", methods=["POST"])
    def create_user():

        if not admin_required():
            return jsonify({"error": "Unauthorized"}), 401

        data = request.get_json(silent=True) or {}

        username = data.get("username", "").strip()

        if not username or len(username) > 100:
            return jsonify({"error": "Invalid username"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"error": "User already exists"}), 409

        token = secrets.token_urlsafe(32)

        user = User(username=username, token_hash=hash_token(token), active=True)

        db.session.add(user)
        db.session.commit()

        # Return the plaintext token only once.
        return jsonify(
            {
                "id": user.id,
                "username": user.username,
                "token": token,
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
                    "active": u.active,
                    "created_at": u.created_at.isoformat(),
                    "last_used": (u.last_used.isoformat() if u.last_used else None),
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
        db.session.commit()

        return jsonify({"message": "User disabled", "user_id": user.id})

    return app
