import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)

    token_hash = db.Column(db.String(64), unique=True, nullable=False)

    active = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    last_used = db.Column(db.DateTime, nullable=True)


class AccessLog(db.Model):
    __tablename__ = "access_logs"

    id = db.Column(db.BigInteger, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    method = db.Column(db.String(20))
    hostname = db.Column(db.String(255))
    status = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
