"""A fake GMshield backend for tests/test_leak.py: the part of the public API quality/sm1/runner.py uses.

`Backend` serves on 127.0.0.1 from a thread. It answers as the backend in test mode with the fake model would: each
material gets two passages; a question's turn cites every passage its campaign's scope allows (campaign and system
tiers, and the other tier when it is on), with one citation event per passage and one reference per material.
Answer deltas carry ANSWER-SECRET, so a test can prove no answer text reaches the record or the result.

It also keeps what the gate reads besides the API: `passages()` ({passage id: version id}, as Postgres' passage
table), `turns()` ({turn id: {job, campaign}}, as turn and conversation) and `worker_log()` (the worker's
retrieval.search_done lines, with `docker logs --timestamps`' prefix).

Behaviours (`Backend(**behaviour)`): `leak` (the start of a material's file name: its passages Livro's turns also
find and cite),
`found_only` (Livro's jobs find the `leak` passages but cite nothing of them), `cite_only` (the start of a material's
file name: Livro's turns send its passages as citation events only, neither found nor in the done references), `error` ({question text: error code}),
`stopped` (question texts whose done event says stopped), `renew_after` (seconds before the session must be renewed).

Part B (tests/test_sm1.py): `given` (a session token the GM already holds: no sign-in), `current` (the account's
current campaign before the run), `say` ({campaign name: {question text: [delta texts]}}: what the answer says after
ANSWER-SECRET, in pieces), `deleted_log` (whether a system deletion logs library.system_deleted), `no_job_log` (question
texts whose job logs no retrieval.search_done line), `no_history` (question texts whose job logs no
conversation.history_read line), `end_session_after` (the session ends, every token refused, once this many turns
exist), `current_status` (the status GET /api/v1/campaigns/current answers instead of 200). It serves the owner-review page view (two pages per material, one
passage each), the system deletion and its preview, and `backend_log()` (conversation.history_read lines with a decoy
of another account's job, and library.system_deleted). `requests` counts every request.

Story 4.3 part C: each system's record types and their records lists (one `spell` type per system, its records those of
the system's materials and of its campaigns' materials, each naming its material as GET /api/v1/materials/{id} names
it), empty unless `records` is on. With `records`, each material also gets one record (`records()`: {record id:
version id}, as Postgres' record table), each turn finds its scope's records (the `records` of its
retrieval.search_done line) and cites each with a record citation event and a record reference; `leak` and
`found_only` treat the leaked material's record as its passages.
"""
from __future__ import annotations

import base64
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

FRONTEND = "gmshield-test-mode-frontend-credential-not-a-secret"   # the test mode's public value
CODE = "stand-in.sm1.leak@example.test"


def _id() -> str:
    return str(uuid.uuid4())


class State:
    def __init__(self, leak=None, found_only=False, error=None, stopped=(), renew_after=900, cite_only=None,
                 given=None, current=None, say=None, deleted_log=True, no_job_log=(), no_history=(),
                 end_session_after=None, current_status=None, records=False):
        self.lock = threading.Lock()
        self.say, self.deleted_log, self.no_job_log = say or {}, deleted_log, set(no_job_log)
        self.no_history, self.end_session_after, self.current_status = set(no_history), end_session_after, current_status
        self.requests = 0
        self.deleting: set[str] = set()
        self.backend_lines: list[str] = [json.dumps({"event": "conversation.history_read", "jobId": "job-decoy",
                                                     "turnId": "turn-decoy", "history": 0})]
        self.leak, self.found_only, self.cite_only = leak, found_only, cite_only
        self.error, self.stopped = error or {}, set(stopped)
        self.renew_after = renew_after
        self.tokens: set[str] = set()
        self.renewals = 0
        self.systems: dict[str, str] = {}                 # id -> name
        self.campaigns: dict[str, dict] = {}              # id -> {name, system, scope}
        self.materials: dict[str, dict] = {}              # id -> {key, version, campaign | systems, state, polls}
        self.uploads: dict[str, dict] = {}
        self.passage_rows: dict[str, str] = {}            # passage id -> version id
        self.with_records = records
        self.record_rows: dict[str, str] = {}             # record id -> version id (Story 4.3 part C)
        self.turn_rows: dict[str, dict] = {}              # turn id -> {job, campaign, events}
        self.log_lines: list[str] = []
        self.current: str | None = current
        if given:
            self.tokens.add(given)
        self.indexing_polls = 0
        self.unauthorized = 0

    # -- scope, as the backend resolves it
    def tier(self, campaign_id: str, m: dict) -> str:
        c = self.campaigns[campaign_id]
        if m.get("campaign") == campaign_id:
            return "campaign"
        if c["system"] in m.get("systems", []):
            return "system"
        return "other"

    def allowed(self, campaign_id: str, rows: dict[str, str] | None = None) -> list[str]:
        """The ids of `rows` (the passages by default; the records, Story 4.3 part C) the campaign's scope allows."""
        rows = self.passage_rows if rows is None else rows
        scope = self.campaigns[campaign_id]["scope"]
        on = {"campaign": scope["campaignTier"], "system": scope["systemTier"], "other": scope["otherTier"]}
        out = []
        for m in self.materials.values():
            if m["state"] == "ready" and on[self.tier(campaign_id, m)]:
                out += [p for p, v in rows.items() if v == m["version"]]
        return out

    def records_of_system(self, system_id: str) -> list[tuple[str, dict]]:
        """(record id, material) of the system's ready materials and of its campaigns' (Story 4.3 part C)."""
        campaigns = {cid for cid, c in self.campaigns.items() if c["system"] == system_id}
        return [(r, m) for r, v in self.record_rows.items() for m in self.materials.values()
                if m["version"] == v and m["state"] == "ready"
                and (system_id in m.get("systems", []) or m.get("campaign") in campaigns)]


class Handler(BaseHTTPRequestHandler):
    server_version = "stub"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    @property
    def st(self) -> State:
        return self.server.state

    def log_message(self, *a):
        pass

    def _send(self, status: int, payload=None, headers: dict | None = None):
        data = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if payload is not None:
            self.send_header("Content-Type", "application/json" if status < 400 else "application/problem+json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _problem(self, status: int, code: str):
        self._send(status, {"status": status, "code": code})

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _json(self) -> dict:
        try:
            return json.loads(self._body() or b"{}")
        except ValueError:
            return {}

    def _authorized(self, session: bool = True) -> bool:
        self.st.requests += 1
        if self.headers.get("Authorization") != f"Bearer {FRONTEND}":
            self.st.unauthorized += 1
            self._problem(401, "service.unauthenticated")
            return False
        if session and self.headers.get("X-Session-Token") not in self.st.tokens:
            self.st.unauthorized += 1
            self._problem(401, "session.required")
            return False
        return True

    def _grant(self) -> dict:
        token = _id()
        self.st.tokens.add(token)
        return {"sessionToken": token, "renewAfterSeconds": self.st.renew_after, "expiresInSeconds": 604800}

    # -- routes
    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        st = self.st
        if path == "/api/v1/sign-in/google":
            if self._authorized(session=False):
                self._body()
                self._send(200, {"attemptToken": "attempt-1", "expiresInSeconds": 600,
                                 "authorizationUrl": "/auth/google/callback?state=state-1&code=stand-in.1.gm%40e.t"})
            return
        if path == "/api/v1/sign-in/google/callback":
            if self._authorized(session=False):
                b = self._json()
                ok = (b.get("attemptToken"), b.get("state"), b.get("code")) == ("attempt-1", "state-1", CODE)
                self._send(200, {"outcome": "username_required"}) if ok else self._problem(400, "sign_in.refused")
            return
        if path == "/api/v1/sign-in/complete":
            if self._authorized(session=False):
                b = self._json()
                ok = b.get("termsAccepted") is True and b.get("username") == "sm1_leak"
                self._send(200, self._grant()) if ok else self._problem(400, "request.invalid")
            return
        if not self._authorized():
            return
        if path == "/api/v1/session/renewal":
            self._body()
            st.tokens.discard(self.headers.get("X-Session-Token"))
            st.renewals += 1
            self._send(200, self._grant())
        elif path == "/api/v1/systems":
            sid = _id()
            st.systems[sid] = self._json().get("name")
            self._send(201, {"id": sid, "name": st.systems[sid], "edition": None, "description": None, "version": 0})
        elif path == "/api/v1/campaigns":
            b = self._json()
            cid = _id()
            st.campaigns[cid] = {"name": b.get("name"), "system": b.get("systemId"),
                                 "scope": {"version": 0, "campaignTier": True, "systemTier": True, "otherTier": False,
                                           "modelKnowledge": False}}
            self._send(201, {"id": cid, "name": b.get("name"), "archived": False, "version": 0, "system": {}})
        elif path == "/api/v1/uploads":
            self._body()
            meta = {}
            for part in (self.headers.get("Upload-Metadata") or "").split(","):
                k, _, v = part.partition(" ")
                meta[k] = base64.b64decode(v).decode()
            uid = _id()
            st.uploads[uid] = meta
            self._send(201, None, {"Location": f"/api/v1/uploads/{uid}", "Tus-Resumable": "1.0.0"})
        elif path.startswith("/api/v1/uploads/") and path.endswith("/completion"):
            uid = path.split("/")[4]
            self._json()
            meta = st.uploads[uid]
            mid, vid = _id(), _id()
            key = meta["filename"]
            m = {"key": key, "version": vid, "state": "waiting", "polls": 0}
            if meta.get("campaign"):
                m["campaign"] = meta["campaign"]
            else:
                m["systems"] = meta["systems"].split(",")
            st.materials[mid] = m
            for _ in range(2):
                st.passage_rows[_id()] = vid
            if st.with_records:
                st.record_rows[_id()] = vid
            self._send(201, {"materialId": mid, "versionId": vid, "state": "waiting"})
        elif path.startswith("/api/v1/materials/") and path.endswith("/accept"):
            self._body()
            m = st.materials.get(path.split("/")[4])
            if not m or m["state"] != "needs_review":
                self._problem(409, "material.action_unavailable")
                return
            m["state"] = "ready"
            self._send(200, {"state": "ready"})
        elif path.startswith("/api/v1/campaigns/") and path.endswith("/turns"):
            self._turn(path.split("/")[4], self._json())
        elif path.startswith("/api/v1/turns/") and path.endswith("/stop"):
            self._body()
            self._send(202, {})
        else:
            self._problem(404, "request.not_found")

    def do_DELETE(self):  # noqa: N802
        if not self._authorized():
            return
        path = urlparse(self.path).path
        st = self.st
        parts = path.strip("/").split("/")
        if parts[:3] == ["api", "v1", "systems"] and len(parts) == 4:
            sid = parts[3]
            if sid not in st.systems or sid in st.deleting:
                self._problem(404, "request.not_found")
                return
            st.deleting.add(sid)
            if st.deleted_log:
                st.backend_lines.append(json.dumps({"event": "library.system_deleted", "systemId": sid,
                                                    "deletionId": _id(), "campaigns": 1}))
            self._send(202, None)
        else:
            self._problem(404, "request.not_found")

    def do_PATCH(self):  # noqa: N802
        if not self._authorized():
            return
        self._body()
        self._send(204, None, {"Upload-Offset": "1", "Tus-Resumable": "1.0.0"})

    def do_PUT(self):  # noqa: N802
        if not self._authorized():
            return
        path = urlparse(self.path).path
        st = self.st
        b = self._json()
        if path == "/api/v1/campaigns/current":
            st.current = b.get("campaignId")
            self._send(200, {"id": st.current})
        elif path.endswith("/scope"):
            c = st.campaigns[path.split("/")[4]]
            if b.get("version") != c["scope"]["version"]:
                self._problem(409, "scope.stale")
                return
            c["scope"] = {"version": c["scope"]["version"] + 1,
                          **{k: b[k] for k in ("campaignTier", "systemTier", "otherTier", "modelKnowledge")}}
            self._send(200, self._scope(path.split("/")[4]))
        else:
            self._problem(404, "request.not_found")

    def _scope(self, cid: str) -> dict:
        st = self.st
        return {**st.campaigns[cid]["scope"],
                "materials": [{"id": mid, "name": "NAME-SECRET", "on": True, "tier": st.tier(cid, m)}
                              for mid, m in st.materials.items() if m["state"] == "ready"]}

    def do_GET(self):  # noqa: N802
        if not self._authorized():
            return
        url = urlparse(self.path)
        path = url.path
        st = self.st
        parts = path.strip("/").split("/")
        if parts[:3] == ["api", "v1", "materials"] and len(parts) == 6 and parts[4] == "pages":
            m = st.materials.get(parts[3])
            if m is None or url.query != "ground=review" or m["state"] not in ("needs_review", "ready"):
                self._problem(404, "request.not_found")
                return
            ids = sorted(p for p, v in st.passage_rows.items() if v == m["version"])
            page = int(parts[5])
            if not 1 <= page <= len(ids):
                self._problem(404, "request.not_found")
                return
            self._send(200, {"page": page, "pageTotal": len(ids), "picture": None, "lines": [],
                             "text": "PASSAGE-SECRET", "passages": [{"id": ids[page - 1], "range": [0, 5]}],
                             "outcome": "read_directly"})
            return
        if path == "/api/v1/campaigns/current":
            if st.current_status:
                self._problem(st.current_status, f"http.{st.current_status}")
            elif st.current is None:
                self._problem(404, "request.not_found")
            else:
                self._send(200, {"id": st.current, "name": "NAME-SECRET"})
            return
        if parts[:3] == ["api", "v1", "systems"] and len(parts) == 5 and parts[4] == "deletion":
            if parts[3] not in st.systems or parts[3] in st.deleting:
                self._problem(404, "request.not_found")
            else:
                self._send(200, {"campaigns": 1, "conversations": 0, "materials": 1})
            return
        if parts[:3] == ["api", "v1", "systems"] and len(parts) == 5 and parts[4] == "record-types":
            if parts[3] not in st.systems or parts[3] in st.deleting:
                self._problem(404, "request.not_found")
                return
            n = len(st.records_of_system(parts[3]))
            self._send(200, {"items": [{"id": f"type-{parts[3]}", "core": "spell", "name": "spell", "records": n,
                                        "version": 0}], "total": 1})
            return
        if parts[:3] == ["api", "v1", "record-types"] and len(parts) == 5 and parts[4] == "records":
            sid = parts[3].removeprefix("type-")
            query = dict(item.split("=", 1) for item in url.query.split("&") if "=" in item)
            limit, offset = int(query.get("limit", "20")), int(query.get("offset", "0"))
            found = st.records_of_system(sid)
            self._send(200, {"items": [{"id": r, "name": "NAME-SECRET", "materialName": f"NAME-SECRET {m['key']}",
                                        "page": 1} for r, m in found[offset:offset + limit]], "total": len(found)})
            return
        if path.startswith("/api/v1/materials/"):
            m = st.materials.get(path.split("/")[4])
            if m is None:
                self._problem(404, "request.not_found")
                return
            m["polls"] += 1
            if m["state"] == "waiting":
                m["state"] = "processing"
            elif m["state"] == "processing":
                m["state"] = "needs_review"
            self._send(200, {"id": path.split("/")[4], "state": m["state"], "name": f"NAME-SECRET {m['key']}"})
        elif path == "/api/v1/conversations/current":
            st.indexing_polls += 1
            pending = st.indexing_polls % 2 == 1
            self._send(200, {"campaignId": st.current, "hasSources": True,
                             "indexing": {"remaining": 3} if pending else None, "indexingFailed": None})
        elif path.endswith("/scope"):
            self._send(200, self._scope(path.split("/")[4]))
        elif path.startswith("/api/v1/turns/") and path.endswith("/events"):
            self._events(path.split("/")[4])
        else:
            self._problem(404, "request.not_found")

    # -- questions
    def _turn(self, cid: str, b: dict):
        st = self.st
        if cid not in st.campaigns or b.get("area") != "questions" or not b.get("question"):
            self._problem(400, "request.invalid")
            return
        tid, job = _id(), _id()
        q = b["question"]
        ids = st.allowed(cid)
        livro = st.campaigns[cid]["name"].split(" · ")[0] == "Livro"
        leaked = []
        if st.leak and livro:
            leaked = [p for p, v in st.passage_rows.items()
                      for m in st.materials.values() if m["version"] == v and m["key"].startswith(st.leak)]
        found = ids + leaked
        cited = ids + ([] if st.found_only else leaked)
        # Story 4.3 part C: the scope's records (and the leaked material's) are found and cited as passages are.
        records = st.allowed(cid, st.record_rows)
        if st.leak and livro:
            records += [r for r, v in st.record_rows.items()
                        for m in st.materials.values() if m["version"] == v and m["key"].startswith(st.leak)]
        cited_records = [r for r in records if not st.found_only or r in st.allowed(cid, st.record_rows)]
        if q not in st.no_history:
            st.backend_lines.append(json.dumps({"timestamp": "2026-11-22T12:00:00.000Z", "level": "INFO",
                                                "event": "conversation.history_read", "jobId": job, "turnId": tid,
                                                "conversationId": _id(), "history": 0}))
        if q not in st.no_job_log:
            st.log_lines.append("2026-11-22T12:00:00.000000000Z " + json.dumps(
            {"timestamp": "2026-11-22T12:00:00.000Z", "level": "INFO", "unit": "lane.answer",
             "event": "retrieval.search_done", "jobId": job, "tiers": 2, "handed": len(found), "ids": found,
             "records": records}))
        events = [("delta", {"text": "ANSWER-SECRET "})]
        events += [("delta", {"text": piece}) for piece in st.say.get(st.campaigns[cid]["name"].split(" · ")[0], {})
                   .get(q, [])]
        if q in st.error:
            events.append(("error", {"code": st.error[q]}))
        else:
            extra = [p for p, v in st.passage_rows.items() for m in st.materials.values()
                     if livro and st.cite_only and m["version"] == v and m["key"].startswith(st.cite_only)]
            events += [("citation", {"passageId": p, "offset": i}) for i, p in enumerate(cited + extra)]
            events += [("citation", {"recordId": r, "offset": 0}) for r in cited_records]
            refs = {}
            for p in cited:
                refs.setdefault(st.passage_rows.get(p), []).append(p)
            references = [{"number": n, "kind": "passage", "page": 1, "passageIds": v, "removed": False,
                           "sectionPath": [], "materialName": "NAME-SECRET"} for n, v in enumerate(refs.values(), 1)]
            for r in cited_records:
                own = sorted(p for p, v in st.passage_rows.items() if v == st.record_rows[r])[:1]
                references.append({"number": len(references) + 1, "kind": "record", "recordId": r,
                                   "recordType": "spell", "name": "NAME-SECRET", "fields": [], "page": 1,
                                   "passageIds": own, "removed": False, "sectionPath": [],
                                   "materialName": "NAME-SECRET"})
            events.append(("done", {"stopped": q in st.stopped, "silent": not cited and not cited_records,
                                    "modelKnowledge": False, "references": references}))
        st.turn_rows[tid] = {"job": job, "campaign": cid, "events": events}
        if st.end_session_after is not None and len(st.turn_rows) >= st.end_session_after:
            st.tokens.clear()
        self._send(201, {"id": tid, "conversationId": _id(), "language": "pt-BR"})

    def _events(self, tid: str):
        t = self.st.turn_rows.get(tid)
        if t is None:
            self._problem(404, "request.not_found")
            return
        last = int(self.headers.get("Last-Event-ID") or 0)
        body = b": keep-alive\n\n"
        for n, (name, data) in enumerate(t["events"], 1):
            if n > last:
                body += f"id: {n}\nevent: {name}\ndata: {json.dumps(data)}\n\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Backend:
    def __init__(self, **behaviour):
        self.state = State(**behaviour)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.state = self.state
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"  # NOSONAR(S5332) a test's loopback stub

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()

    # what the gate reads besides the API
    def passages(self) -> dict[str, str]:
        return dict(self.state.passage_rows)

    def records(self) -> dict[str, str]:
        """As Postgres' record table (Story 4.3 part C): {record id: version id}."""
        return dict(self.state.record_rows)

    def turns(self) -> dict[str, dict]:
        return {t: {"job": r["job"], "campaign": r["campaign"]} for t, r in self.state.turn_rows.items()}

    def worker_log(self) -> str:
        return "\n".join(self.state.log_lines) + "\n"

    def backend_log(self) -> str:
        """As `docker logs --timestamps`: each line after the time it was written (here one fixed past time)."""
        return "".join(f"2026-11-22T11:00:00.000000000Z {line}\n" for line in self.state.backend_lines)
