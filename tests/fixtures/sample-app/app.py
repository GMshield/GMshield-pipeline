"""Tiny HTTP service used only to test the GMshield pipeline end to end."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; form-action 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def body_for(path: str) -> tuple[int, bytes]:
    if path == "/health":
        return 200, b'{"status":"ok"}'
    if path == "/":
        return 200, b'{"service":"sample"}'
    return 404, b'{"error":"not found"}'


class Handler(BaseHTTPRequestHandler):
    server_version = "sample"
    sys_version = ""

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self._send(*body_for(self.path.split("?", 1)[0]))

    def log_message(self, *args):  # keep container logs quiet
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
