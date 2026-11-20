#!/usr/bin/env python3
"""A fake GMshield backend (and a fake `docker`) for tests/test_sm2.py.

As a module: `Backend` serves the part of the public API `gmshield_ci sm2` uses, on 127.0.0.1, from a thread.
Each question's text names its scenario (SCENARIOS); answer deltas carry ANSWER-SECRET and page lines carry
PASSAGE-SECRET, so a test can prove neither reaches the result or standard output.

Linked under the name `docker`: answers `docker inspect --format <fmt> <container>` from the JSON in
$SM2_DOCKER_STATE ({container: {networks, env, labels, image}}); an unknown container exits 1.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CAMPAIGN = "0190a0b0-0000-7000-8000-000000000002"
MATERIAL = "0190a0b0-0000-7000-8000-000000000003"
PICTURE = {"width": 1000, "height": 1400}

# Page views by page number. Page 10: two columns; P1 (left, its phrase split by a line-end hyphen and a
# ligature), P2 (right, no phrase). Page 20: a text page (P4 by range, after a character outside the BMP).
# Pages 30-31: P5 runs over the page break. Page 99: a page outside every expected page.
VIEWS = {
    10: {"picture": PICTURE, "text": None, "outcome": "read_directly", "pageTotal": 40,
         "lines": [{"text": "Heading PASSAGE-SECRET", "box": [0.1, 0.05, 0.9, 0.08]},
                   {"text": "The ﬁre-", "box": [0.1, 0.10, 0.5, 0.12]},
                   {"text": "ball deals eight dice PASSAGE-SECRET", "box": [0.1, 0.12, 0.5, 0.14]},
                   {"text": "below the passage", "box": [0.1, 0.14, 0.5, 0.16]},
                   {"text": "Other column PASSAGE-SECRET", "box": [0.55, 0.10, 0.9, 0.12]}],
         "passages": [{"id": "P1", "boxes": [[0.1, 0.10, 0.5, 0.14]]},
                      {"id": "P2", "boxes": [[0.55, 0.10, 0.9, 0.12]]}]},
    20: {"picture": None, "lines": [], "outcome": "read_directly", "pageTotal": 40,
         "text": "\U0001d504 Intro. The range holds the answer phrase here PASSAGE-SECRET. Outro.",
         "passages": [{"id": "P4", "range": [9, 61]}]},
    30: {"picture": PICTURE, "text": None, "outcome": "read_directly", "pageTotal": 40,
         "lines": [{"text": "the answer con-", "box": [0.1, 0.9, 0.5, 0.92]}],
         "passages": [{"id": "P5", "boxes": [[0.1, 0.9, 0.5, 0.92]]}]},
    31: {"picture": PICTURE, "text": None, "outcome": "read_directly", "pageTotal": 40,
         "lines": [{"text": "tinues here PASSAGE-SECRET", "box": [0.1, 0.05, 0.5, 0.07]},
                   {"text": "unrelated", "box": [0.1, 0.5, 0.5, 0.52]}],
         "passages": [{"id": "P5", "boxes": [[0.1, 0.05, 0.5, 0.07]]},
                      {"id": "P6", "boxes": [[0.1, 0.5, 0.5, 0.52]]}]},
    99: {"picture": PICTURE, "text": None, "outcome": "read_directly", "pageTotal": 120,
         "lines": [{"text": "nothing useful PASSAGE-SECRET", "box": [0.1, 0.1, 0.5, 0.12]}],
         "passages": [{"id": "P9", "boxes": [[0.1, 0.1, 0.5, 0.12]]}]},
}


def ref(number: int, page: int, *ids: str) -> dict:
    return {"number": number, "page": page, "sectionPath": ["Spells", "Fireball"], "passageIds": list(ids),
            "materialName": "SRD.pdf", "removed": False}


# scenario -> (events, options). Events: ("delta"|"citation"|"done"|"error", data) or ("sleep", seconds).
SCENARIOS = {
    "pass-boxes": [("delta", {"text": "ANSWER-SECRET one"}), ("citation", {"offset": 3, "passageId": "P1"}),
                   ("delta", {"text": " ANSWER-SECRET two"}),
                   ("done", {"silent": False, "stopped": False, "references": [ref(1, 10, "P1")]})],
    "pass-range": [("delta", {"text": "ANSWER-SECRET"}),
                   ("done", {"silent": False, "stopped": False, "references": [ref(1, 99, "P9"), ref(2, 20, "P4")]})],
    "pass-span": [("delta", {"text": "ANSWER-SECRET"}),
                  ("done", {"silent": False, "stopped": False, "references": [ref(1, 30, "P5")]})],
    "phrase-missing": [("delta", {"text": "ANSWER-SECRET"}),
                       ("done", {"silent": False, "stopped": False, "references": [ref(1, 10, "P2")]})],
    "wrong-page": [("delta", {"text": "ANSWER-SECRET"}),
                   ("done", {"silent": False, "stopped": False, "references": [ref(1, 99, "P9")]})],
    "silent": [("delta", {"text": "ANSWER-SECRET the sources are silent"}),
               ("done", {"silent": True, "stopped": False, "references": []})],
    "error": [("delta", {"text": "ANSWER-SECRET"}), ("error", {"code": "model.unavailable"})],
    "timeout": [("delta", {"text": "ANSWER-SECRET"}), ("hang", None)],
    "slow": [("sleep", 0.4), ("delta", {"text": "ANSWER-SECRET"}),
             ("done", {"silent": False, "stopped": False, "references": [ref(1, 10, "P1")]})],
    "no-picture": [("delta", {"text": "ANSWER-SECRET"}),
                   ("done", {"silent": False, "stopped": False, "references": [ref(1, 10, "P1")]})],
    "cut": [("delta", {"text": "ANSWER-SECRET"}), ("cut", None),
            ("done", {"silent": False, "stopped": False, "references": [ref(1, 10, "P1")]})],
    "stopped": [("delta", {"text": "ANSWER-SECRET"}),
                ("done", {"silent": False, "stopped": True, "references": [ref(1, 10, "P2")]})],
    "chunk-cut": [("chunked", None), ("delta", {"text": "ANSWER-SECRET"}),
                  ("done", {"silent": False, "stopped": False, "references": [ref(1, 10, "P1")]})],
    "burst": [("sleep", 0.3), ("delta", {"text": "ANSWER-SECRET"}), ("sleep", 0.3),
              ("done", {"silent": False, "stopped": False, "references": [ref(1, 10, "P1")]})],
}


class Backend:
    def __init__(self, credential: str = "cred-SECRET", token: str = "tok-0", renew_after: int = 900,
                 renewals_allowed: int | None = None, material_states: list[str] | None = None,
                 indexing: dict | None = None, has_sources: bool = True,
                 renewal_required_after_turns: int | None = None):
        self.credential, self.token, self.renew_after = credential, token, renew_after
        self.previous: set[str] = set()
        self.renewals = 0
        self.renewals_allowed = renewals_allowed
        self.material_states = list(material_states or ["waiting", "processing", "processing", "needs_review"])
        self.indexing = indexing
        self.has_sources = has_sources
        self.renewal_required_after_turns = renewal_required_after_turns
        self.turns: dict[str, str] = {}             # turn id -> scenario
        self.stopped: list[str] = []
        self.discarded: list[str] = []
        self.upload: bytes = b""
        self.upload_length = 0
        self.calls: list[tuple[str, str]] = []
        self.open_turns = 0
        self.max_open_turns = 0
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def finished(self, turn: str) -> None:
        with self.lock:
            self.open_turns -= 1

    def next_state(self) -> str:
        with self.lock:
            return self.material_states.pop(0) if len(self.material_states) > 1 else self.material_states[0]

    def _handler(self):
        backend = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, status: int, body: dict | bytes | None = None, headers: dict | None = None,
                     ctype: str = "application/json") -> None:
                data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else b"")
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if data:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def problem(self, status: int, code: str) -> None:
                self.send(status, {"type": f"urn:gmshield:problem:{code}", "title": code, "status": status,
                                   "category": code.split(".")[0], "code": code, "params": {}, "traceId": "t"},
                          ctype="application/problem+json")

            def body(self) -> bytes:
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def authorised(self) -> bool:
                if self.headers.get("Authorization") != f"Bearer {backend.credential}":
                    self.problem(401, "service.unauthenticated")
                    return False
                return True

            def session_ok(self) -> bool:
                if self.headers.get("X-Session-Token") != backend.token:
                    self.problem(401, "session.required")
                    return False
                return True

            def do_GET(self):
                self.route("GET")

            def do_POST(self):
                self.route("POST")

            def do_PATCH(self):
                self.route("PATCH")

            def route(self, method: str) -> None:
                path = self.path
                backend.calls.append((method, path))
                if not self.authorised():
                    return
                if path == "/api/v1/session/renewal" and method == "POST":
                    return self.renew()
                if not self.session_ok():
                    return
                parts = path.strip("/").split("/")
                if path == "/api/v1/campaigns/current":
                    return self.send(200, {"id": CAMPAIGN, "name": "c", "system": {"id": "s", "name": "s"}})
                if path == "/api/v1/conversations/current":
                    return self.send(200, {"campaignId": CAMPAIGN, "hasSources": backend.has_sources,
                                           "indexing": backend.indexing,
                                           "indexingFailed": None})
                if path == f"/api/v1/campaigns/{CAMPAIGN}/turns" and method == "POST":
                    limit = backend.renewal_required_after_turns
                    if limit is not None and len(backend.turns) >= limit:
                        return self.problem(401, "session.renewal_required")
                    question = json.loads(self.body())["question"]
                    with backend.lock:
                        turn = f"turn-{len(backend.turns) + 1}"
                        backend.turns[turn] = question
                        backend.open_turns += 1
                        backend.max_open_turns = max(backend.max_open_turns, backend.open_turns)
                    return self.send(201, {"id": turn, "conversationId": "conv", "language": "en"})
                if parts[:3] == ["api", "v1", "turns"] and len(parts) == 5 and parts[4] == "events":
                    return self.events(parts[3])
                if parts[:3] == ["api", "v1", "turns"] and len(parts) == 5 and parts[4] == "stop":
                    backend.stopped.append(parts[3])
                    return self.send(204)
                if parts[:3] == ["api", "v1", "turns"] and len(parts) >= 8 and parts[4] == "references":
                    return self.page(parts[3], int(parts[7]), picture=len(parts) == 9)
                if path == "/api/v1/uploads" and method == "POST":
                    meta = dict(item.split(" ") for item in self.headers["Upload-Metadata"].split(","))
                    assert base64.b64decode(meta["campaign"]).decode() == CAMPAIGN
                    assert base64.b64decode(meta["filename"]).decode().endswith(".pdf")
                    backend.upload_length = int(self.headers["Upload-Length"])
                    return self.send(201, headers={"Location": "/api/v1/uploads/u1", "Tus-Resumable": "1.0.0"})
                if path == "/api/v1/uploads/u1" and method == "PATCH":
                    data = self.body()
                    want = "sha256 " + base64.b64encode(hashlib.sha256(data).digest()).decode()
                    if self.headers.get("Upload-Checksum") != want or len(data) != backend.upload_length:
                        return self.problem(460, "upload.part_checksum_mismatch")
                    backend.upload = data
                    return self.send(204, headers={"Upload-Offset": str(len(data)), "Tus-Resumable": "1.0.0"})
                if path == "/api/v1/uploads/u1/completion" and method == "POST":
                    if json.loads(self.body())["sha256"] != hashlib.sha256(backend.upload).hexdigest():
                        return self.problem(422, "upload.file_checksum_mismatch")
                    return self.send(201, {"materialId": MATERIAL, "versionId": "v", "state": "waiting"})
                if path == f"/api/v1/materials/{MATERIAL}" and method == "GET":
                    return self.send(200, {"id": MATERIAL, "name": "x.pdf", "state": backend.next_state(),
                                           "actions": []})
                if path == f"/api/v1/materials/{MATERIAL}/discard" and method == "POST":
                    state = backend.material_states[0]
                    if state not in ("needs_review", "failed"):
                        return self.problem(409, "material.action_unavailable")
                    backend.discarded.append(MATERIAL)
                    backend.material_states = ["discarded"]
                    return self.send(200, {"id": MATERIAL, "name": "x.pdf", "state": "discarded", "actions": []})
                return self.problem(404, "request.not_found")

            def renew(self) -> None:
                tok = self.headers.get("X-Session-Token")
                if tok in backend.previous:
                    return self.problem(409, "session.already_renewed")
                if tok != backend.token:
                    return self.problem(401, "session.required")
                if backend.renewals_allowed is not None and backend.renewals >= backend.renewals_allowed:
                    return self.problem(401, "session.required")
                backend.renewals += 1
                backend.previous.add(backend.token)
                backend.token = f"tok-{backend.renewals}"
                self.send(200, {"sessionToken": backend.token, "renewAfterSeconds": backend.renew_after,
                                "expiresInSeconds": 604800})

            def page(self, turn: str, page: int, picture: bool) -> None:
                scenario = backend.turns.get(turn)
                view = VIEWS.get(page)
                if scenario is None or view is None:
                    return self.problem(404, "request.not_found")
                if picture:
                    if scenario == "no-picture" or view["picture"] is None:
                        return self.problem(404, "request.not_found")
                    return self.send(200, b"RIFF0000WEBP", ctype="image/webp")
                self.send(200, {"page": page, **view})

            def events(self, turn: str) -> None:
                scenario = backend.turns.get(turn)
                if scenario is None:
                    return self.problem(404, "request.not_found")
                after = int(self.headers.get("Last-Event-ID") or 0)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                if scenario == "chunk-cut" and after == 0:
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                seq = 0
                try:
                    for kind, data in SCENARIOS[scenario]:
                        if kind == "sleep":
                            time.sleep(data)
                        elif kind == "hang":
                            while turn not in backend.stopped:
                                self.wfile.write(b": keep-alive\n\n")
                                self.wfile.flush()
                                time.sleep(0.1)
                            backend.finished(turn)
                            return
                        elif kind == "cut":
                            if after == 0:
                                return                  # the stream ends early once; the client reopens
                        elif kind == "chunked":
                            if after == 0:              # one whole chunk with the first event, then half a chunk
                                event = b'id: 1\nevent: delta\ndata: {"text": "ANSWER-SECRET"}\n\n'
                                self.wfile.write(b"%x\r\n%s\r\n" % (len(event), event))
                                self.wfile.write(b"400\r\nid: 2\nevent: do")
                                self.wfile.flush()
                                return
                        else:
                            seq += 1
                            if seq <= after:
                                continue
                            self.wfile.write(f"id: {seq}\nevent: {kind}\ndata: {json.dumps(data)}\n\n".encode())
                            self.wfile.flush()
                            if kind in ("done", "error"):
                                backend.finished(turn)
                                return
                finally:
                    self.close_connection = True

        return Handler


def docker_main() -> int:
    """`docker inspect --format <fmt> <container>` from $SM2_DOCKER_STATE."""
    args = sys.argv[1:]
    state = json.loads(Path(os.environ["SM2_DOCKER_STATE"]).read_text())
    if len(args) != 4 or args[0] != "inspect" or args[1] != "--format":
        return 2
    fmt, name = args[2], args[3]
    c = state.get(name)
    if c is None:
        print(f"Error: No such object: {name}", file=sys.stderr)
        return 1
    if fmt == "{{json .NetworkSettings.Networks}}":
        print(json.dumps({n: {"IPAddress": ip} for n, ip in c.get("networks", {}).items()}))
    elif fmt == "{{range .Config.Env}}{{println .}}{{end}}":
        print("\n".join(c.get("env", [])))
    elif fmt == "{{json .Config.Labels}}":
        print(json.dumps(c.get("labels")))
    elif fmt == "{{.Config.Image}}":
        print(c.get("image", ""))
    else:
        return 2
    return 0


if __name__ == "__main__" and Path(sys.argv[0]).name == "docker":
    sys.exit(docker_main())
