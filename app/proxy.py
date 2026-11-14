import os
import socket
import select
import hashlib
import secrets
import http.client

from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from admin import create_app
from models import db, User, AccessLog


flask_app = create_app()

ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.getenv("ALLOWED_HOSTS", "").split(",")
    if h.strip()
}

MAX_REQUEST_SIZE = int(
    os.getenv("MAX_REQUEST_SIZE", "10485760")
)


def authenticate(handler):

    value = handler.headers.get(
        "Proxy-Authorization", ""
    )

    scheme, _, token = value.partition(" ")

    if scheme.lower() != "bearer" or not token:
        return None

    digest = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with flask_app.app_context():

        user = User.query.filter_by(
            token_hash=digest,
            active=True
        ).first()

        if user:
            return user.id

    return None

def validate_destination(host, port):

    host = host.lower().rstrip(".")

    if host not in ALLOWED_HOSTS:
        raise ValueError("Destination not allowed")

    if port not in (80, 443):
        raise ValueError("Destination port not allowed")

    results = socket.getaddrinfo(
        host,
        port,
        type=socket.SOCK_STREAM
    )

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
        print("PROXY:", format % args)

    def authorize(self):

        user_id = authenticate(self)

        if not user_id:
            self.send_error(407, "Proxy authentication required")
            return None

        return user_id

    def record(self, user_id, host, status):

        with flask_app.app_context():

            log = AccessLog(
                user_id=user_id,
                method=self.command,
                hostname=host[:255],
                status=status
            )

            db.session.add(log)

            user = db.session.get(User, user_id)

            if user:
                from datetime import datetime, timezone
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

            remote = socket.create_connection(
                (host, port),
                timeout=10
            )

            self.send_response(200, "Connection Established")
            self.end_headers()

            self.connection.settimeout(60)
            remote.settimeout(60)

            sockets = [self.connection, remote]

            while True:

                readable, _, exceptional = select.select(
                    sockets, [], sockets, 60
                )

                if exceptional or not readable:
                    break

                for source in readable:

                    destination = (
                        remote if source is self.connection
                        else self.connection
                    )

                    data = source.recv(65536)

                    if not data:
                        return

                    destination.sendall(data)

            self.record(user_id, host, 200)

        except Exception:
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

            host = validate_destination(
                parsed.hostname,
                parsed.port or 80
            )

            length = int(self.headers.get("Content-Length", "0"))

            if length < 0 or length > MAX_REQUEST_SIZE:
                self.send_error(413, "Request too large")
                return

            body = self.rfile.read(length) if length else None

            conn = http.client.HTTPConnection(
                host,
                parsed.port or 80,
                timeout=30
            )

            headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in (
                    "proxy-authorization",
                    "proxy-connection",
                    "connection",
                    "host",
                    "transfer-encoding"
                )
            }

            headers["Host"] = host

            path = parsed.path or "/"

            if parsed.query:
                path += "?" + parsed.query

            conn.request(
                self.command,
                path,
                body=body,
                headers=headers
            )

            response = conn.getresponse()

            self.send_response(response.status)

            for key, value in response.getheaders():

                if key.lower() not in (
                    "connection",
                    "transfer-encoding",
                    "keep-alive"
                ):
                    self.send_header(key, value)

            self.send_header("Connection", "close")
            self.end_headers()

            while True:
                chunk = response.read(65536)

                if not chunk:
                    break

                self.wfile.write(chunk)

            self.close_connection = True

            self.record(user_id, host, response.status)

            conn.close()

        except Exception:
            self.send_error(502, "Proxy request failed")

    do_GET = forward_http
    do_POST = forward_http
    do_PUT = forward_http
    do_DELETE = forward_http
    do_HEAD = forward_http
    do_OPTIONS = forward_http
    do_PATCH = forward_http


if __name__ == "__main__":

    server = ThreadingHTTPServer(
        (
            os.getenv("PROXY_HOST", "0.0.0.0"),
            int(os.getenv("PROXY_PORT", "8888"))
        ),
        ProxyHandler
    )

    server.daemon_threads = True

    print("Forward proxy listening on port 8888")

    server.serve_forever()