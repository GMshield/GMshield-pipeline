"""The end-to-end test's stand-in Ollama (Story 2.9): Python's standard library only, no model.

Run with the worker image's Python, `python -I stand_in_ollama.py [port]` (default 11434, on every address
of the container). It answers only what the worker asks of Ollama:

    POST /api/embed {"model": ..., "input": [text, ...], "truncate": ...}  ->  {"embeddings": [[768 numbers], ...]}

Each vector is deterministic and never zero: every word of the text (lower case, letters and digits) adds 1 to
a few positions chosen by the word's SHA-256, plus a small constant everywhere. Texts that share words get
close vectors, so a question finds the passage that holds its words. A malformed embed body gets 400; every other
request is a 404.
Nothing is logged but the method, the path and the status.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DIMENSIONS = 768
PORT = 11434
MAX_BODY = 16 * 1024 * 1024
_WORD = re.compile(r"[0-9a-z]+")
_SLOTS = 4                       # positions one word adds to


def vector(text: str) -> list[float]:
    """The deterministic, non-zero, finite vector of `text`."""
    v = [0.01] * DIMENSIONS
    for word in _WORD.findall(text.lower()):
        digest = hashlib.sha256(word.encode()).digest()
        for i in range(_SLOTS):
            v[int.from_bytes(digest[2 * i:2 * i + 2], "big") % DIMENSIONS] += 1.0
    return v


def embeddings(body: object) -> list[list[float]] | None:
    """The answer to an embed request's body, or None when it is not one."""
    if not isinstance(body, dict):
        return None
    texts = body.get("input")
    if isinstance(texts, str):
        texts = [texts]
    if not isinstance(texts, list) or not texts or not all(isinstance(t, str) for t in texts):
        return None
    return [vector(t) for t in texts]


class Handler(BaseHTTPRequestHandler):
    server_version = "stand-in-ollama"
    sys_version = ""

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 - the http.server name
        if self.path != "/api/embed":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            self._send(400, {"error": "bad request"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            body = None
        found = embeddings(body)
        if found is None:
            self._send(400, {"error": "bad request"})
            return
        self._send(200, {"model": (body or {}).get("model", ""), "embeddings": found})

    def _not_found(self) -> None:
        self._send(404, {"error": "not found"})

    do_GET = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_found  # noqa: N815

    def do_HEAD(self) -> None:  # noqa: N802 - the http.server name
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt: str, *args) -> None:   # the request line holds no text; the body is never logged
        sys.stderr.write(f"{self.command} {self.path.split('?')[0][:80]} {args[1] if len(args) > 1 else ''}\n")


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else PORT
    server = ThreadingHTTPServer(("", port), Handler)
    print(f"stand-in Ollama listening on {port}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()  # NOSONAR(S5332) plain HTTP on the run's internal network, which has no TLS
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
