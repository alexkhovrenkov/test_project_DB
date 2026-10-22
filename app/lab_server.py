"""
lab_server.py - the small HTTP API (and static file server) of the Interactive Lab.

    make lab                      build the frontend and start everything on http://127.0.0.1:8000
    python app/lab_server.py      the same, without building (serves frontend/dist if it exists)

Endpoints (JSON):
    GET  /api/health        is MariaDB reachable? server version
    GET  /api/examples      the playground's preloaded demonstrations (app/lab_examples.py)
    POST /api/query         {"role": "professor", "sql": "SELECT ..."} -> rows or MariaDB's refusal
    GET  /api/stats         dataset size, accounts and their authentication plugins, TLS settings
    GET  /api/scenarios     the benchmark scenarios
    POST /api/benchmark     {"scenario": "tls-versions", "runs": 30} -> real measurements

Only the Python standard library: no web framework is needed for six endpoints.
The server listens on 127.0.0.1 only and has no debug mode. It never sends a
credential to the browser: the demo accounts' passwords exist only in this
process (admin.Harness). POST requests must be JSON, and the Host header must
be this machine, so another web site open in the same browser cannot drive the
API (no CORS headers are sent, and DNS rebinding is refused).
"""

import argparse
import json
import mimetypes
import os
import signal
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pymysql

from database import PROJECT_DIR, ConfigError
from lab import Lab, LabError, LabUnavailable, scenarios

DIST_DIR = PROJECT_DIR / "frontend" / "dist"
MAX_BODY_BYTES = 64 * 1024
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


class LabHandler(BaseHTTPRequestHandler):
    server_version = "MariaDBInteractiveLab/1.0"
    lab = None          # set by make_server()
    dist_dir = DIST_DIR

    # --- plumbing -------------------------------------------------------------------------------

    def log_message(self, format, *args):   # noqa: A002 - signature of the base class
        if not getattr(self.server, "quiet", False):
            sys.stderr.write(f"[lab] {self.address_string()} {format % args}\n")

    def _send(self, status, body, content_type="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("application/json"):
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status, message, **extra):
        self._send(status, {"error": message, **extra})

    def _host_is_local(self):
        host = (self.headers.get("Host") or "").strip().lower()
        name = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        return name in ALLOWED_HOSTS

    def _read_json(self):
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            raise LabError("Send the request body as application/json.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise LabError("Invalid Content-Length.") from None
        if length > MAX_BODY_BYTES:
            raise LabError("The request body is too large.")
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise LabError("The request body is not valid JSON.") from None
        if not isinstance(payload, dict):
            raise LabError("The request body must be a JSON object.")
        return payload

    def _dispatch(self, routes):
        if not self._host_is_local():
            self._error(HTTPStatus.FORBIDDEN, "The lab only answers requests addressed to this machine.")
            return
        path = self.path.split("?", 1)[0]
        handler = routes.get(path)
        if handler is None:
            if path.startswith("/api/"):
                self._error(HTTPStatus.NOT_FOUND, f"No such endpoint: {path}")
            elif self.command == "GET":
                self._static(path)
            else:
                self._error(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed.")
            return
        try:
            self._send(HTTPStatus.OK, handler())
        except LabError as error:
            self._error(HTTPStatus.BAD_REQUEST, str(error))
        except (LabUnavailable, ConfigError) as error:
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, str(error), database="down")
        except pymysql.MySQLError as error:
            self._error(HTTPStatus.BAD_GATEWAY, f"MariaDB error: {error}")

    # --- routes -------------------------------------------------------------------------------

    def do_GET(self):   # noqa: N802 - name required by BaseHTTPRequestHandler
        self._dispatch({
            "/api/health": self.lab.health,
            "/api/examples": self.lab.examples,
            "/api/stats": self.lab.stats,
            "/api/scenarios": lambda: {"scenarios": scenarios()},
        })

    def do_POST(self):   # noqa: N802
        self._dispatch({
            "/api/query": self._query,
            "/api/benchmark": self._benchmark,
        })

    def _query(self):
        payload = self._read_json()
        return self.lab.run(payload.get("role"), payload.get("sql"))

    def _benchmark(self):
        payload = self._read_json()
        return self.lab.benchmark(payload.get("scenario"), payload.get("runs"))

    # --- the built frontend -----------------------------------------------------------------------

    def _static(self, path):
        root = Path(self.dist_dir).resolve()
        if not (root / "index.html").is_file():
            self._send(HTTPStatus.SERVICE_UNAVAILABLE,
                       b"The frontend is not built yet. Run 'make lab' (or: cd frontend && npm ci && npm run build).\n"
                       b"The API is available under /api/.\n", "text/plain; charset=utf-8")
            return
        target = (root / path.lstrip("/")).resolve()
        if root not in target.parents and target != root:
            self._error(HTTPStatus.NOT_FOUND, "Not found.")
            return
        if not target.is_file():
            target = root / "index.html"   # single-page app: the frontend handles the route
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "image/svg+xml"}:
            content_type += "; charset=utf-8"
        self._send(HTTPStatus.OK, target.read_bytes(), content_type)


def make_server(lab, host="127.0.0.1", port=8000, dist_dir=DIST_DIR, quiet=False):
    """An HTTP server for `lab` (not started). port=0 picks a free port."""
    handler = type("BoundLabHandler", (LabHandler,), {"lab": lab, "dist_dir": dist_dir})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.quiet = quiet
    return server


def _stop_on_sigterm(signum, frame):
    """`kill`, a process manager or a closing terminal: clean up exactly like Ctrl+C."""
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description="MariaDB Interactive Lab: API + frontend on 127.0.0.1.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("LAB_PORT", "8000")))
    arguments = parser.parse_args(argv)
    mimetypes.add_type("application/javascript", ".js")
    previous_handler = signal.signal(signal.SIGTERM, _stop_on_sigterm)
    lab = Lab()
    server = make_server(lab, port=arguments.port)
    print(f"MariaDB Interactive Lab: http://127.0.0.1:{server.server_port}/   (Ctrl+C stops it)", flush=True)
    health = lab.health()
    if health["database"] == "up":
        print(f"Connected to MariaDB {health['server_version']} over verified TLS; demo accounts ready.", flush=True)
    else:
        print(f"WARNING: {health['error']}\nThe lab starts anyway and retries on every request.", flush=True)
    if not (DIST_DIR / "index.html").is_file():
        print("Note: frontend/dist is missing - run 'make lab' to build it (the API works without it).", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping; removing the lab's temporary administrator account.", flush=True)
    finally:
        server.server_close()
        lab.close()
        signal.signal(signal.SIGTERM, previous_handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
