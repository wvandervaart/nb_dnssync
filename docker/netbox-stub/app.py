"""Minimal stand-in for NetBox's REST API, used only by docker-compose
integration testing so `python -m app.bootstrap` has a reachable NetBox to
query. Always answers every GET with an empty NetBox-shaped paginated list -
the --prune scenario relies on NetBox genuinely having zero IPs/devices, so
bootstrap treats every record left in BIND by earlier webhook-flow test
steps as an orphan. Not a general-purpose NetBox mock.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EMPTY = json.dumps({"count": 0, "next": None, "previous": None, "results": []}).encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(EMPTY)))
        self.end_headers()
        self.wfile.write(EMPTY)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
