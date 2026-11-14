import os
import socket
import select
import hashlib
import secrets
import time
import http.client
import ipaddress
import logging
from datetime import datetime, timezone

from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from admin import create_app
from models import db, User, AccessLog


flask_app = create_app()

ALLOWED_HOSTS = {
    h.strip().lower() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()
}

MAX_REQUEST_SIZE = int(os.getenv("MAX_REQUEST_SIZE", "10485760"))

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

logger = logging.getLogger("proxy")


def authenticate(handler):

    value = handler.headers.get("Proxy-Authorization", "")

    scheme, _, token = value.partition(" ")

    if scheme.lower() != "bearer" or not token:
        return None

    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

    with flask_app.app_context():
        user = User.query.filter_by(token_hash=digest, active=True).first()

        if user:
            return user.id

    return None


def validate_destination(host, port):

    host = host.lower().rstrip(".")

    if host not in ALLOWED_HOSTS:
        raise ValueError("Destination not allowed")

    if port not in (80, 443):
        raise ValueError("Destination port not allowed")

    results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)

    if not results:
        raise ValueError("DNS resolution failed")

    for result in results:
        ip = ipaddress.ip_address(result[4][0])

        if not ip.is_global:
            raise ValueError("Non-public destination")

    return host


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Avoid logging credentials or complete URLs.
        self.logger.info("client=%s:%s %s", self.client_address[0], self.client_address[1], format % args)

    def authorize(self):

        user_id = authenticate(self)

        if not user_id:
            logger.warning(
                "auth failed client=%s:%s path=%r",
                self.client_address[0],
                self.client_address[1],
                self.path,
            )
            self.send_error(407, "Proxy authentication required")
            return None

        logger.info(
            "auth ok user_id=%s client=%s:%s path=%r",
            user_id,
            self.client_address[0],
            self.client_address[1],
            self.path,
        )

        return user_id

    def record(self, user_id, host, status):

        with flask_app.app_context():
            log = AccessLog(
                user_id=user_id, method=self.command, hostname=host[:255], status=status
            )

            db.session.add(log)

            user = db.session.get(User, user_id)

            if user:
                user.last_used = datetime.now(timezone.utc)

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
        resp = client.open(
            self.path,
            method=self.command,
            data=body,
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
        "forward proxy listening on %s:%s",
        os.getenv("PROXY_HOST", "0.0.0.0"),
        os.getenv("PROXY_PORT", "8888"),
    )

    server.serve_forever()
