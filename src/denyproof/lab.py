"""Loopback-only test API with deliberately vulnerable authorization handlers."""
import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

CANARY = "demo-alice-invoice-7b839f"
TOKENS = {"lab-alice-token": "alice", "lab-bob-token": "bob"}


def configuration(origin):
    return {"origin": origin,
            "identities": {name: {"token_env": name.upper() + "_TOKEN",
                                   "probe": {"path": "/me", "pointer": "/user", "equals": name}}
                           for name in ("alice", "bob")},
            "cases": [{"id": name, "owner": "alice", "subject": "bob", "path": "/" + name,
                       "proof": [{"pointer": "/invoice/canary", "equals": CANARY}]}
                      for name in ("leaky-200", "leaky-403", "secure", "login-page", "redirect")]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        user = TOKENS.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
        data = {"invoice": {"canary": CANARY, "amount": 1450}}
        status = 200
        content_type = "application/json"
        if self.path == "/me":
            status, data = (200, {"user": user}) if user else (401, {"error": "unauthorized"})
        elif not user:
            status, data = 401, {"error": "unauthorized"}
        elif self.path == "/leaky-200":
            pass
        elif self.path == "/leaky-403":
            status = 200 if user == "alice" else 403
        elif self.path == "/secure":
            if user != "alice":
                status, data = 403, {"error": "forbidden"}
        elif self.path == "/login-page":
            if user != "alice":
                content_type, data = "text/html", "<html>Log in</html>"
        elif self.path == "/redirect":
            if user != "alice":
                status, data = 302, {"message": "redirect"}
        else:
            status, data = 404, {"error": "not found"}
        body = (json.dumps(data) if content_type == "application/json" else data).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if status == 302:
            self.send_header("Location", "http://example.invalid/never-follow")
        self.end_headers()
        self.wfile.write(body)


@contextmanager
def lab():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
