"""A tiny, DELIBERATELY VULNERABLE demo API used to validate the scanner.

All weaknesses are *simulated* with in-memory data: there is no database and no real code
execution. It binds to 127.0.0.1 only. Never expose it to a network.

    python -m lab.vuln_lab --port 8099

Then add http://127.0.0.1:8099 as a target with "local lab" enabled
(ALLOW_LOCAL_LAB_TARGETS=true) and spec URL http://127.0.0.1:8099/openapi.json.

Tokens: lab-token-alice, lab-token-bob (normal users), lab-token-admin (administrator).
"""

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOKENS = {"lab-token-alice": "alice", "lab-token-bob": "bob", "lab-token-admin": "admin"}
ORDERS = {
    1: {"id": 1, "owner": "alice", "total": 42},
    2: {"id": 2, "owner": "alice", "total": 7},
    3: {"id": 3, "owner": "bob", "total": 19},
}
ITEMS = ["sample item", "another sample", "sample gadget"]

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Vulnerable Lab API", "version": "1.0"},
    "servers": [{"url": "/api"}],
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/health": {"get": {"security": [], "summary": "Health"}},
        "/ping": {"get": {"security": [], "summary": "Unthrottled ping"}},
        "/limited": {"get": {"security": [], "summary": "Throttled ping"}},
        "/search": {
            "get": {
                "security": [],
                "summary": "Search (SQL injectable)",
                "parameters": [
                    {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
        "/orders/{order_id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "summary": "Get order (BOLA)",
                "parameters": [
                    {
                        "name": "order_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
            }
        },
        "/safe/orders/{order_id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "summary": "Get order (enforced)",
                "parameters": [
                    {
                        "name": "order_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
            }
        },
        "/account": {
            "get": {"security": [{"bearerAuth": []}], "summary": "Account (auth NOT enforced)"}
        },
        "/profile": {
            "get": {"security": [{"bearerAuth": []}], "summary": "Profile (auth enforced)"}
        },
        "/weak-auth/me": {
            "get": {"security": [{"bearerAuth": []}], "summary": "Accepts any bearer value"}
        },
        "/admin/users": {
            "get": {"security": [{"bearerAuth": []}], "summary": "Admin users (BFLA)"}
        },
        "/admin/secure-users": {
            "get": {"security": [{"bearerAuth": []}], "summary": "Admin users (enforced)"}
        },
        "/legacy/status": {"get": {"security": [], "deprecated": True, "summary": "Old status"}},
    },
}

_limited_hits: list[float] = []
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "vuln-lab/1.2.3"

    def log_message(self, *args) -> None:  # silence
        return

    # -- helpers --
    def _user(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return TOKENS.get(auth[7:]) if auth.startswith("Bearer ") else None

    def _send(self, status: int, data, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PythonLab/3.1")  # version banner (misconfig)
        origin = self.headers.get("Origin")
        if origin:  # reflected CORS with credentials (misconfig)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- routes --
    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        user = self._user()

        if path == "/openapi.json":
            return self._send(200, SPEC)
        if path == "/api/health":
            return self._send(200, {"status": "ok"})
        if path == "/api/ping":  # intentionally never rate limited
            return self._send(200, {"pong": True})
        if path == "/api/limited":
            with _lock:
                now = time.monotonic()
                _limited_hits[:] = [t for t in _limited_hits if now - t < 60]
                _limited_hits.append(now)
                over = len(_limited_hits) > 8
            hdr = {"X-RateLimit-Limit": "8"}
            if over:
                return self._send(429, {"error": "slow down"}, {**hdr, "Retry-After": "30"})
            return self._send(200, {"ok": True}, hdr)
        if path == "/api/legacy/status":
            return self._send(200, {"legacy": True})
        if path == "/api/search":  # SQL injection (simulated)
            q = (query.get("q") or [""])[0]
            m = re.fullmatch(r"(.*)' AND '1'='(\d)", q)
            if m:  # boolean-based behaviour
                term = m.group(1)
                hits = [i for i in ITEMS if term in i] if m.group(2) == "1" else []
                return self._send(200, {"results": hits})
            if "'" in q or '"' in q or "\\" in q:
                return self._send(
                    500,
                    {
                        "error": "You have an error in your SQL syntax; check the manual "
                        "that corresponds to your MySQL server version for the right syntax to use near '"
                        + q[:20]
                        + "'"
                    },
                )
            return self._send(200, {"results": [i for i in ITEMS if q in i]})
        if path == "/api/account":  # auth declared but NOT enforced
            return self._send(200, {"account": "demo", "plan": "free"})
        if path == "/api/profile":
            if not user:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"user": user})
        if path == "/api/weak-auth/me":  # accepts any bearer value
            if not self.headers.get("Authorization", "").startswith("Bearer "):
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"user": "anyone"})
        m = re.fullmatch(r"/api/orders/(\d+)", path)
        if m:  # BOLA: any authenticated user can read any order
            if not user:
                return self._send(401, {"error": "unauthorized"})
            order = ORDERS.get(int(m.group(1)))
            return self._send(200, order) if order else self._send(404, {"error": "not found"})
        m = re.fullmatch(r"/api/safe/orders/(\d+)", path)
        if m:
            if not user:
                return self._send(401, {"error": "unauthorized"})
            order = ORDERS.get(int(m.group(1)))
            if not order or order["owner"] != user:
                return self._send(403, {"error": "forbidden"})
            return self._send(200, order)
        if path == "/api/admin/users":  # BFLA: no role check
            if not user:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"users": ["alice", "bob", "admin"]})
        if path == "/api/admin/secure-users":
            if not user:
                return self._send(401, {"error": "unauthorized"})
            if user != "admin":
                return self._send(403, {"error": "forbidden"})
            return self._send(200, {"users": ["alice", "bob", "admin"]})
        # verbose error page (misconfig)
        return self._send(
            404,
            {
                "error": "not found",
                "trace": "Traceback (most recent call last):\n"
                '  File "/usr/lib/python3/lab/app.py", line 88, in <module>\nKeyError: '
                + path[:40],
            },
        )


def start(host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, int]:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("the vulnerable lab may only bind to loopback")
    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def reset() -> None:
    with _lock:
        _limited_hits.clear()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    srv, port = start(port=args.port)
    print(f"Vulnerable lab listening on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
