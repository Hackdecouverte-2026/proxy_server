import os
import base64
import socket
import select
import time
import http.client
import ipaddress
import logging
from datetime import datetime, timezone

from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from admin import create_app
from auth import hash_token, utcnow
from models import db, User, AccessLog, Credential


flask_app = create_app()

PROXY_REALM = flask_app.config["PROXY_REALM"]

ALLOWED_HOSTS = {
    h.strip().lower() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()
}

MAX_REQUEST_SIZE = int(os.getenv("MAX_REQUEST_SIZE", "10485760"))

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

logger = logging.getLogger("proxy")


def authenticate(handler):
    """RFC 7617 Basic only: base64(entra-upn:device-credential).

    The username carries the identity, the password is the per-device
    credential issued by /enroll. Returns (user_id, credential_id, username).
    """

    value = handler.headers.get("Proxy-Authorization", "")

    scheme, _, payload = value.partition(" ")

    if scheme.lower() != "basic":
        return None

    try:
        decoded = base64.b64decode(payload, validate=True).decode("utf-8")
    except Exception:
        return None

    username, separator, token = decoded.partition(":")

    username = username.strip().lower()

    if not separator or not username or not token:
        return None

    digest = hash_token(token)

    with flask_app.app_context():
        credential = Credential.query.filter_by(token_hash=digest).first()

        if not credential or not credential.usable(utcnow()):
            return None

        user = db.session.get(User, credential.user_id)

        if not user or not user.active or user.username != username:
            return None

        return user.id, credential.id, user.username


class DeniedError(ValueError):
    """Destination refused by policy. ``reason`` is stored in access_logs."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def validate_destination(host, port):

    host = host.lower().rstrip(".")

    if host not in ALLOWED_HOSTS:
        raise DeniedError("not_allowed", "Destination not allowed")

    if port not in (80, 443):
        raise DeniedError("port_not_allowed", "Destination port not allowed")

    results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)

    if not results:
        raise ValueError("DNS resolution failed")

    for result in results:
        ip = ipaddress.ip_address(result[4][0])

        if not ip.is_global:
            raise DeniedError("non_public", "Non-public destination")

    return host


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Avoid logging credentials or complete URLs.
        logger.info(
            "client=%s:%s %s",
            self.client_address[0],
            self.client_address[1],
            format % args,
        )

    def challenge(self):
        # RFC 7235: a 407 must carry Proxy-Authenticate so clients
        # know to prompt and retry.
        self.send_response(407, "Proxy Authentication Required")
        self.send_header(
            "Proxy-Authenticate", f'Basic realm="{PROXY_REALM}", charset="UTF-8"'
        )
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    credential_id = None
    username = None

    def authorize(self):

        identity = authenticate(self)

        if not identity:
            logger.warning(
                "auth failed client=%s:%s path=%r",
                self.client_address[0],
                self.client_address[1],
                self.path,
            )
            self.deny(None, 407, "auth_failed", "Proxy Authentication Required")
            return None

        user_id, credential_id, username = identity

        self.credential_id = credential_id
        self.username = username

        logger.info(
            "auth ok user=%s user_id=%s credential_id=%s client=%s:%s path=%r",
            username,
            user_id,
            credential_id,
            self.client_address[0],
            self.client_address[1],
            self.path,
        )

        return user_id

    def request_host(self):
        """Best-effort target host of the current request, for logging."""

        if self.command == "CONNECT":
            return self.path.rsplit(":", 1)[0].lower()

        return (urlsplit(self.path).hostname or "").lower()

    def deny(self, user_id, status, reason, message):
        """Reply with an error and log the rejected request."""

        try:
            self.record(user_id, self.request_host(), status, reason)
        except Exception:
            logger.exception("failed to record denied request")

        if status == 407:
            self.challenge()
        else:
            self.send_error(status, message)

    def record(self, user_id, host, status, reason=None):

        with flask_app.app_context():
            log = AccessLog(
                user_id=user_id,
                credential_id=self.credential_id,
                method=self.command,
                hostname=host[:255],
                status=status,
                reason=reason,
            )

            db.session.add(log)

            now = datetime.now(timezone.utc)

            user = db.session.get(User, user_id) if user_id else None

            if user:
                user.last_used = now

            credential = (
                db.session.get(Credential, self.credential_id)
                if self.credential_id
                else None
            )

            if credential:
                credential.last_used = now

            db.session.commit()

    def do_CONNECT(self):

        user_id = self.authorize()

        if user_id is None:
            return

        try:
            host, port = self.path.rsplit(":", 1)
            port = int(port)

            host = validate_destination(host, port)

            logger.info("tunnel start user_id=%s host=%s port=%s", user_id, host, port)

            remote = socket.create_connection((host, port), timeout=10)

            self.send_response(200, "Connection Established")
            self.end_headers()

            self.connection.settimeout(60)
            remote.settimeout(60)

            sockets = [self.connection, remote]
            started = time.monotonic()
            bytes_up = 0
            bytes_down = 0

            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)

                if exceptional or not readable:
                    break

                eof = False

                for source in readable:
                    destination = (
                        remote if source is self.connection else self.connection
                    )

                    data = source.recv(65536)

                    if not data:
                        eof = True
                        break

                    destination.sendall(data)

                    if source is self.connection:
                        bytes_up += len(data)
                    else:
                        bytes_down += len(data)

                if eof:
                    break

            self.record(user_id, host, 200)

            logger.info(
                "tunnel end user_id=%s host=%s up=%d down=%d total=%d dur=%.2fs",
                user_id,
                host,
                bytes_up,
                bytes_down,
                bytes_up + bytes_down,
                time.monotonic() - started,
            )

        except DeniedError as exc:
            logger.warning(
                "tunnel denied user_id=%s path=%r reason=%s",
                user_id,
                self.path,
                exc.reason,
            )
            self.deny(user_id, 403, exc.reason, "Forbidden")

        except Exception:
            logger.exception(
                "tunnel failed user_id=%s path=%r", user_id, self.path
            )
            self.send_error(502, "Proxy connection failed")

        finally:
            try:
                remote.close()
            except Exception:
                pass

    def forward_http(self):

        user_id = self.authorize()

        if user_id is None:
            return

        try:
            parsed = urlsplit(self.path)

            if parsed.scheme != "http" or not parsed.hostname:
                self.send_error(400, "Invalid HTTP proxy URL")
                return

            host = validate_destination(parsed.hostname, parsed.port or 80)

            length = int(self.headers.get("Content-Length", "0"))

            if length < 0 or length > MAX_REQUEST_SIZE:
                self.send_error(413, "Request too large")
                return

            body = self.rfile.read(length) if length else None

            conn = http.client.HTTPConnection(host, parsed.port or 80, timeout=30)

            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower()
                not in (
                    "proxy-authorization",
                    "proxy-connection",
                    "connection",
                    "host",
                    "transfer-encoding",
                )
            }

            headers["Host"] = host

            path = parsed.path or "/"

            if parsed.query:
                path += "?" + parsed.query

            conn.request(self.command, path, body=body, headers=headers)

            response = conn.getresponse()

            self.send_response(response.status)

            for key, value in response.getheaders():
                if key.lower() not in ("connection", "transfer-encoding", "keep-alive"):
                    self.send_header(key, value)

            self.send_header("Connection", "close")
            self.end_headers()

            bytes_out = 0

            while True:
                chunk = response.read(65536)

                if not chunk:
                    break

                self.wfile.write(chunk)

                bytes_out += len(chunk)

            self.close_connection = True

            self.record(user_id, host, response.status)

            logger.info(
                "forward user_id=%s %s %s -> HTTP %s (%d bytes)",
                user_id,
                self.command,
                host,
                response.status,
                bytes_out,
            )

            conn.close()

        except DeniedError as exc:
            logger.warning(
                "forward denied user_id=%s path=%r reason=%s",
                user_id,
                self.path,
                exc.reason,
            )
            self.deny(user_id, 403, exc.reason, "Forbidden")

        except Exception:
            logger.exception(
                "forward failed user_id=%s path=%r", user_id, self.path
            )
            self.send_error(502, "Proxy request failed")

    do_PUT = forward_http
    do_DELETE = forward_http
    do_HEAD = forward_http
    do_OPTIONS = forward_http
    do_PATCH = forward_http

    def serve_local(self):
        """Serve an origin-form request (e.g. POST /auth) via the Flask app."""

        length = int(self.headers.get("Content-Length", "0"))

        if length < 0 or length > MAX_REQUEST_SIZE:
            self.send_error(413, "Request too large")
            return

        body = self.rfile.read(length) if length else b""

        client = flask_app.test_client()

        # /enroll needs the Entra bearer token, admin routes the admin key,
        # /dev/enroll the dev key.
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() in ("authorization", "x-admin-key", "x-dev-key")
        }

        resp = client.open(
            self.path,
            method=self.command,
            data=body,
            headers=headers,
            content_type=self.headers.get("Content-Type"),
        )

        self.send_response(resp.status_code)

        for key, value in resp.headers:
            if key.lower() == "content-type":
                self.send_header(key, value)

        self.send_header("Content-Length", str(len(resp.data)))
        self.end_headers()

        self.wfile.write(resp.data)

        logger.info(
            "local %s %s -> HTTP %s (%d bytes)",
            self.command,
            self.path,
            resp.status_code,
            len(resp.data),
        )

        self.close_connection = True

    def do_GET(self):
        if urlsplit(self.path).scheme:
            self.forward_http()
        else:
            self.serve_local()

    def do_POST(self):
        if urlsplit(self.path).scheme:
            self.forward_http()
        else:
            self.serve_local()


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        (os.getenv("PROXY_HOST", "0.0.0.0"), int(os.getenv("PROXY_PORT", "8888"))),
        ProxyHandler,
    )

    server.daemon_threads = True

    logger.info(
        "forward proxy (Basic auth, realm=%r) listening on %s:%s",
        PROXY_REALM,
        os.getenv("PROXY_HOST", "0.0.0.0"),
        os.getenv("PROXY_PORT", "8888"),
    )

    server.serve_forever()
