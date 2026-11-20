"""SM-2: are answers sourced? The fixed SRD 5.2.1 question set, asked through the backend's public API.

Run on roberto-server, in ~/gmshield-ci/runner (Story 2.9):

    python3 -m gmshield_ci sm2 --session-file ~/.config/gmshield/sm2-session

It asks the 50 questions of quality/sm2/questions.json one at a time in the current campaign, then fires a
burst of 5 at once while a generated 60-page PDF is being processed, and records four gates:
- sourced: at least 9 in 10 answers cite a passage holding one of the question's answer phrases (SM-2);
- first words: at least 9 in 10 answers send their first delta within 5 s of the turn's creation (NFR-14);
- references open: every reference of every answer opens (its page view, and its picture when it has one);
- burst: the 5 questions asked during ingestion all end in done, none in error (NFR-17).
Exit status 0 only when all four pass, 1 when a gate fails, 2 when the run cannot start or must stop (no
session, no target, indexing still running, a renewal refused).

Passages are matched by phrase, never by id (ids change at every ingestion): a cited passage is rebuilt from the
reference's page view (the lines its boxes overlap, or its range of a text page's text, plus its part on the next
page), normalised (NFKC, casefold, whitespace collapsed, a hyphen at a line end joined) and searched.

The result goes to ~/gmshield-ci/artifacts/quality/sm2/<UTC yyyy-mm-dd-HHMMSS>-<backend release>/ as result.json
and summary.md: ids, pages, section paths, timings, verdicts and error codes. No answer text and no passage text
reaches the result, standard output or a log. The bearer credential is read from the backend container's
environment at run time and never printed or written; the session token lives only in the session file, which
the runner rewrites (mode 600) after each renewal.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import math
import os
import re
import threading
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import RUNNER_DIR, load_settings
from .dockerops import capture

QUESTIONS = RUNNER_DIR / "quality" / "sm2" / "questions.json"
SERVICES = ("backend", "frontend", "worker")
LANGUAGES = ("en", "pt-BR")
MAX_PHRASE_WORDS = 15
BACKEND_PORT = 8080
# The backend serves plain HTTP on the internal app network only (no host port, README "Pipeline contract");
# the runner reaches it there by the container's address, as the frontend does.
SCHEME = "http"
EXIT_PASS, EXIT_FAIL, EXIT_STOPPED = 0, 1, 2
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
_HYPHEN_BREAK = re.compile(r"(?<=\w)-[ \t]*\n\s*(?=\w)")
_SPACE = re.compile(r"\s+")
_QUOTES = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "­": None})


@dataclass
class Limits:
    """The run's limits; tests shrink the waits."""
    question_timeout: float = 300.0       # no done within this many seconds: the turn is stopped
    first_words_ms: int = 5000            # NFR-14
    pass_share: float = 0.9               # SM-2 and NFR-14: 9 in 10
    read_timeout: float = 20.0            # the stream sends a keep-alive every 15 s
    poll_every: float = 2.0
    processing_wait: float = 900.0        # the burst material reaching `processing`
    review_wait: float = 3600.0           # ... then `needs_review` or `failed`, to discard it
    burst_size: int = 5
    burst_pages: int = 60


class SessionStopped(Exception):
    """The session cannot go on (renewal refused, session over): the run stops with exit status 2."""


class Refused(Exception):
    """The run cannot start (no target, no campaign, indexing still running...): exit status 2."""


# ------------------------------------------------------------------ normalising and matching (pure)

def normalise(text: str, keep_hyphen: bool = False) -> str:
    """NFKC, typographic quotes folded, soft hyphens dropped, a hyphen at a line end joined (or kept, with the
    line break removed), casefolded, whitespace collapsed."""
    t = unicodedata.normalize("NFKC", text).translate(_QUOTES)
    t = _HYPHEN_BREAK.sub("-" if keep_hyphen else "", t)
    return _SPACE.sub(" ", t.casefold()).strip()


def holds_phrase(text: str, phrases: list[str]) -> bool:
    """Whether the text holds one of the phrases. A line-end hyphen is tried joined ("in-\\ncludes") and kept
    ("two-\\nhanded"), so a rebuild is lenient, never strict."""
    variants = (normalise(text), normalise(text, keep_hyphen=True))
    return any(p and any(p in v for v in variants) for p in (normalise(x) for x in phrases))


def _overlaps(a: list, b: list) -> bool:
    """Two [left, top, right, bottom] boxes share an area."""
    try:
        return min(a[2], b[2]) - max(a[0], b[0]) > 0 and min(a[3], b[3]) - max(a[1], b[1]) > 0
    except (IndexError, TypeError):
        return False


def passage_text(view: dict, passage_id: str) -> str | None:
    """The passage's text on this page view: the lines its boxes overlap (a picture page), or its range of the
    page's text in code points (a text page). None when the passage is not on the page."""
    for p in view.get("passages") or []:
        if p.get("id") != passage_id:
            continue
        rng, text = p.get("range"), view.get("text")
        if rng and isinstance(text, str) and len(rng) == 2:
            return text[int(rng[0]):int(rng[1])]
        boxes = p.get("boxes") or []
        return "\n".join(line.get("text", "") for line in view.get("lines") or []
                         if any(_overlaps(line.get("box") or [], b) for b in boxes))
    return None


# ------------------------------------------------------------------ the question set

def load_questions(path: Path) -> list[dict]:
    qs = json.loads(path.read_text(encoding="utf-8"))
    problems = check_questions(qs, exact=path.resolve() == QUESTIONS.resolve())
    if problems:
        raise Refused(f"{path}: " + "; ".join(problems))
    return qs


def check_questions(qs: object, exact: bool = True) -> list[str]:
    """What is wrong with a question set. `exact`: the fixed SM-2 set (50, 25 per language, 3+ exact names)."""
    if not isinstance(qs, list) or not qs:
        return ["not a non-empty list"]
    out, ids = [], set()
    for i, q in enumerate(qs):
        where = f"entry {i}"
        if not isinstance(q, dict):
            out.append(f"{where}: not an object")
            continue
        for key, kind in (("id", str), ("language", str), ("question", str), ("pages", list), ("phrases", list)):
            if not isinstance(q.get(key), kind) or not q.get(key):
                out.append(f"{where}: {key} missing or empty")
        if q.get("id") in ids:
            out.append(f"{where}: duplicate id {q.get('id')}")
        ids.add(q.get("id"))
        if q.get("language") not in LANGUAGES:
            out.append(f"{where}: language must be one of {LANGUAGES}")
        if not all(isinstance(p, int) and p >= 1 for p in q.get("pages") or []):
            out.append(f"{where}: pages must be page numbers")
        for ph in q.get("phrases") or []:
            if not isinstance(ph, str) or not ph.strip() or len(ph.split()) > MAX_PHRASE_WORDS:
                out.append(f"{where}: each phrase is 1 to {MAX_PHRASE_WORDS} words")
    if exact:
        langs = [q.get("language") for q in qs if isinstance(q, dict)]
        if len(qs) != 50 or langs.count("en") != 25 or langs.count("pt-BR") != 25:
            out.append("the SM-2 set is 50 questions, 25 in Portuguese and 25 in English")
        if sum(1 for q in qs if isinstance(q, dict) and q.get("exactName")) < 3:
            out.append("the SM-2 set has at least 3 exact-name questions")
    return out


# ------------------------------------------------------------------ the backend

@dataclass
class Target:
    base: str                     # scheme://address:port, no trailing slash
    credential: str = field(repr=False)
    backend_container: str = "gmshield-backend"
    network: str = "gmshield-app"


def _inspect(container: str, fmt: str) -> tuple[int, str]:
    """`docker inspect --format`; (127, "") when Docker is missing. Its output is never logged."""
    try:
        return capture(["docker", "inspect", "--format", fmt, container])
    except OSError:
        return 127, ""


def resolve_target(backend_container: str, network: str) -> Target:
    """The backend's address on `network` and the frontend's service credential, both from `docker inspect`."""
    rc, out = _inspect(backend_container, "{{json .NetworkSettings.Networks}}")
    if rc != 0 or not out:
        raise Refused(f"container {backend_container} not found")
    try:
        ip = (json.loads(out).get(network) or {}).get("IPAddress")
    except (json.JSONDecodeError, AttributeError):
        ip = None
    if not ip:
        raise Refused(f"container {backend_container} has no address on network {network}")
    rc, env = _inspect(backend_container, "{{range .Config.Env}}{{println .}}{{end}}")
    cred = next((line.split("=", 1)[1] for line in env.splitlines()
                 if line.startswith("GMSHIELD_FRONTEND_CREDENTIAL=")), "") if rc == 0 else ""
    if not cred:
        raise Refused(f"container {backend_container} has no GMSHIELD_FRONTEND_CREDENTIAL")
    return Target(f"{SCHEME}://{ip}:{BACKEND_PORT}", cred, backend_container, network)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):      # the API never redirects; a redirect is an error here
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


@dataclass
class Reply:
    status: int
    headers: dict
    body: bytes

    def json(self) -> dict:
        try:
            v = json.loads(self.body or b"{}")
            return v if isinstance(v, dict) else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    @property
    def code(self) -> str:
        """The problem's code, or http.<status>."""
        return str(self.json().get("code") or f"http.{self.status}")


class Session:
    """The session token: read from the session file, renewed when due, written back after each renewal."""

    def __init__(self, path: Path):
        self.path = path
        raw = path.read_text().strip() if path.is_file() else ""
        # The cookie's value is <token>.<renew-after>; the file holds the token, but a whole value is accepted.
        token, dot, suffix = raw.rpartition(".")
        self.token = token if dot and suffix.isdigit() else raw
        if not self.token:
            raise Refused(f"no session token in {path} (sign in, then save the cookie's token there)")
        self.renew_at = 0.0           # unknown age: renew at the first chance
        self.renewals = 0

    def save(self) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(self.token + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)


class Api:
    def __init__(self, target: Target, session: Session):
        self.t = target
        self.session = session
        self._renew_lock = threading.Lock()

    def headers(self, extra: dict | None = None) -> dict:
        return {"Authorization": f"Bearer {self.t.credential}", "X-Session-Token": self.session.token,
                "Accept": "application/json", **(extra or {})}

    def open(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None,
             timeout: float = 30.0):
        req = urllib.request.Request(self.t.base + path, data=body, method=method, headers=self.headers(headers))
        return _OPENER.open(req, timeout=timeout)

    def call(self, method: str, path: str, payload: dict | None = None, *, body: bytes | None = None,
             headers: dict | None = None, timeout: float = 30.0) -> Reply:
        if payload is not None:
            body = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json", **(headers or {})}
        try:
            with self.open(method, path, body, headers, timeout) as r:
                return Reply(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read())
        except urllib.error.HTTPError as e:
            try:
                data = e.read()
            except OSError:
                data = b""
            finally:
                e.close()
            return Reply(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, data)
        except (OSError, http.client.HTTPException) as e:   # URLError included; a body cut mid-chunk too
            return Reply(0, {}, json.dumps({"code": f"backend.unreachable ({type(e).__name__})"}).encode())

    def renew_if_due(self, force: bool = False) -> None:
        """Renews the session when its renew-after time has passed. A refusal stops the run."""
        with self._renew_lock:
            if not force and time.monotonic() < self.session.renew_at:
                return
            # Never retried: a renewal whose reply was lost may have rotated the token already, and a retry would
            # present the retired token.
            r = self.call("POST", "/api/v1/session/renewal")
            if r.status == 0 or r.status >= 500:
                raise SessionStopped(f"session renewal got no answer ({r.code}): the token may have rotated; "
                                     "sign in again and save the new token")
            if r.status != 200:
                why = r.code
                if r.status == 409:
                    why += " (the saved token was renewed elsewhere: save the browser's current token)"
                raise SessionStopped(f"session renewal refused: {why}")
            g = r.json()
            token = g.get("sessionToken")
            if not isinstance(token, str) or not token:
                raise SessionStopped("session renewal answered no token")
            self.session.token = token
            self.session.save()
            self.session.renewals += 1
            after = g.get("renewAfterSeconds")
            after = after if isinstance(after, int) and after >= 0 else 900
            self.session.renew_at = time.monotonic() + after * 0.8      # renew a little before it is due

    def checked(self, r: Reply) -> Reply:
        """A 401 session.required (the session is over) or session.renewal_required stops the run."""
        if r.status == 401 and r.code in ("session.required", "session.renewal_required"):
            raise SessionStopped(f"{r.code}: the session cannot go on")
        return r


# ------------------------------------------------------------------ one question

@dataclass
class Answer:
    turn_id: str | None = None
    ask_ms: int | None = None
    first_words_ms: int | None = None
    total_ms: int | None = None
    done: dict | None = None
    error: str | None = None
    timed_out: bool = False
    deltas: int = 0
    citations: int = 0


def _sse_events(resp, on_event: Callable[[str, str, str | None], bool], deadline: float) -> bool:
    """Reads one SSE response; calls on_event(name, data, id) per event. True when on_event asked to stop;
    False when the stream ended or the deadline passed (keep-alive comments never extend it)."""
    name, data, ev_id = "message", [], None
    while time.monotonic() < deadline:
        raw = resp.readline()
        if not raw:
            return False
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data and on_event(name, "\n".join(data), ev_id):
                return True
            name, data, ev_id = "message", [], None
            continue
        if line.startswith(":"):
            continue
        key, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if key == "event":
            name = value
        elif key == "data":
            data.append(value)
        elif key == "id":
            ev_id = value
    return False


def ask(api: Api, campaign_id: str, question: str, lim: Limits,
        on_created: Callable[[], None] | None = None) -> Answer:
    """Asks one question and follows its event stream to done or error (or the timeout, which stops the turn).
    Only timings, counts, the done event's references and the error code are kept: never the answer's text.
    `on_created` is called once the turn exists (or its creation failed)."""
    a = Answer()
    t0 = time.monotonic()
    try:
        r = api.checked(api.call("POST", f"/api/v1/campaigns/{campaign_id}/turns", {"question": question}))
    finally:
        if on_created:
            on_created()
    created = time.monotonic()
    a.ask_ms = round((created - t0) * 1000)
    if r.status != 201 or not r.json().get("id"):
        a.error = f"ask:{r.code}"
        return a
    a.turn_id = str(r.json()["id"])
    deadline = created + lim.question_timeout
    last_id: str | None = None

    def on_event(name: str, data: str, ev_id: str | None) -> bool:
        nonlocal last_id
        if ev_id:
            last_id = ev_id
        if name == "delta":
            a.deltas += 1
            if a.first_words_ms is None:
                a.first_words_ms = round((time.monotonic() - created) * 1000)
        elif name == "citation":
            a.citations += 1
        elif name == "done":
            try:
                a.done = json.loads(data)
            except json.JSONDecodeError:
                a.error = "stream.malformed_done"
            return True
        elif name == "error":
            try:
                a.error = str(json.loads(data).get("code") or "error")
            except (json.JSONDecodeError, AttributeError):
                a.error = "error"
            return True
        return False

    while a.done is None and a.error is None:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        extra = {"Accept": "text/event-stream"}
        if last_id:
            extra["Last-Event-ID"] = last_id
        try:
            with api.open("GET", f"/api/v1/turns/{a.turn_id}/events", headers=extra,
                          timeout=min(lim.read_timeout, max(left, 0.1))) as resp:
                _sse_events(resp, on_event, deadline)
        except urllib.error.HTTPError as e:
            with e:
                reply = Reply(e.code, {}, e.read() if e.fp else b"")
            api.checked(reply)
            if e.code < 500:
                a.error = f"events:{reply.code}"
                break
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
        except (OSError, http.client.HTTPException):   # a read timeout or a cut stream: reopen after the last event
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    if a.done is None and a.error is None:
        a.timed_out = True
        api.call("POST", f"/api/v1/turns/{a.turn_id}/stop")
    a.total_ms = round((time.monotonic() - created) * 1000)
    return a


def check_references(api: Api, answer: Answer, phrases: list[str] | None) -> tuple[list[dict], bool]:
    """Opens every reference of the answer (page view, and picture when the page has one) and, with phrases,
    rebuilds the cited passages and looks for a phrase. Returns (reference records, any phrase found)."""
    refs, found = [], False
    for ref in (answer.done or {}).get("references") or []:
        n, page = ref.get("number"), ref.get("page")
        ids = [str(x) for x in ref.get("passageIds") or []]
        rec = {"number": n, "page": page, "sectionPath": ref.get("sectionPath") or [], "passageIds": ids,
               "removed": bool(ref.get("removed")), "view": None, "picture": None, "nextView": None,
               "matched": False}
        base = f"/api/v1/turns/{answer.turn_id}/references/{n}/pages"
        v = api.checked(api.call("GET", f"{base}/{page}"))
        rec["view"] = v.status
        view = v.json() if v.status == 200 else {}
        if v.status == 200 and view.get("picture"):
            rec["picture"] = api.checked(api.call("GET", f"{base}/{page}/picture", timeout=60)).status
        rec["opens"] = v.status == 200 and (not view.get("picture") or rec["picture"] == 200)
        if phrases and v.status == 200:
            texts = {i: passage_text(view, i) or "" for i in ids}
            matched = any(holds_phrase(t, phrases) for t in texts.values())
            total = view.get("pageTotal")
            if not matched and isinstance(page, int) and isinstance(total, int) and page < total:
                nv = api.checked(api.call("GET", f"{base}/{page + 1}"))
                rec["nextView"] = nv.status
                if nv.status == 200:
                    nxt = nv.json()
                    for i in ids:
                        more = passage_text(nxt, i)
                        if more:
                            texts[i] = f"{texts[i]}\n{more}"
                    matched = any(holds_phrase(t, phrases) for t in texts.values())
            rec["matched"] = matched
            found = found or matched
        refs.append(rec)
    return refs, found


def judge(q: dict, answer: Answer, refs: list[dict], found: bool) -> tuple[str, str | None]:
    """(verdict, reason). Reasons: an error event's code, timeout, silent, stopped, phrase_missing (a cited page
    is one of the expected pages, but no cited passage holds a phrase), wrong_page."""
    if answer.error:
        return "fail", answer.error
    if answer.timed_out or answer.done is None:
        return "fail", "timeout"
    if answer.done.get("silent"):
        return "fail", "silent"
    if found:
        return "pass", None
    if answer.done.get("stopped"):
        return "fail", "stopped"
    expected = set(q.get("pages") or [])
    return "fail", "phrase_missing" if any(r.get("page") in expected for r in refs) else "wrong_page"


def _ended(a: Answer) -> str:
    if a.error:
        return "error"
    return "done" if a.done is not None else "timeout"


def run_question(api: Api, campaign_id: str, q: dict, lim: Limits, check_phrases: bool = True,
                 on_created: Callable[[], None] | None = None) -> dict:
    a = ask(api, campaign_id, q["question"], lim, on_created)
    refs, found = check_references(api, a, q.get("phrases") if check_phrases else None)
    if check_phrases:
        verdict, reason = judge(q, a, refs, found)
    else:                                         # the burst: only whether the answer ended in done
        verdict = "done" if _ended(a) == "done" else "fail"
        reason = None if verdict == "done" else (a.error or "timeout")
    return {"id": q["id"], "language": q.get("language"), "part": q.get("part"),
            "exactName": bool(q.get("exactName")), "turnId": a.turn_id, "ended": _ended(a), "verdict": verdict,
            "reason": reason,
            "askMs": a.ask_ms, "firstWordsMs": a.first_words_ms, "totalMs": a.total_ms, "deltas": a.deltas,
            "citations": a.citations, "silent": bool((a.done or {}).get("silent")),
            "stopped": bool((a.done or {}).get("stopped")), "timedOut": a.timed_out, "error": a.error,
            "expectedPages": q.get("pages") or [], "citedPages": sorted({r["page"] for r in refs
                                                                          if isinstance(r.get("page"), int)}),
            "references": refs}


# ------------------------------------------------------------------ the burst

def generated_pdf(pages: int, stamp: str) -> bytes:
    """A text-only PDF of `pages` pages of generated filler (no library text), unique per run (`stamp`)."""
    words = ("amber basalt cobalt delta ember fjord granite harbor indigo juniper kelp lantern meadow nickel "
             "orchard pebble quartz river saffron timber umber valley willow xenon yarrow zephyr").split()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for n in range(1, pages + 1):
        lines = [f"SM-2 burst filler, run {stamp}, page {n} of {pages}."]
        seed = hashlib.sha256(f"{stamp}/{n}".encode()).digest()        # 32 bytes: one word choice each
        lines += [" ".join(words[seed[(row * 12 + col) % 32] % len(words)] for col in range(12)) + "."
                  for row in range(36)]
        text = "".join(f"({line}) Tj T* " for line in lines)
        stream = f"BT /F1 11 Tf 14 TL 56 780 Td {text}ET".encode()
        objs.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream))
        content = len(objs)
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents %d 0 R "
                    b"/Resources << /Font << /F1 3 0 R >> >> >>" % content)
        kids.append(len(objs))
    objs[1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(b"%d 0 R" % k for k in kids), len(kids))
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def upload(api: Api, campaign_id: str, name: str, data: bytes) -> str:
    """tus upload into the campaign; returns the material id."""
    meta = ",".join(f"{k} {base64.b64encode(v.encode()).decode()}" for k, v in
                    (("filename", name), ("campaign", campaign_id)))
    tus = {"Tus-Resumable": "1.0.0"}
    r = api.checked(api.call("POST", "/api/v1/uploads", body=b"",
                             headers={**tus, "Upload-Length": str(len(data)), "Upload-Metadata": meta}))
    location = r.headers.get("location", "")
    if r.status != 201 or not location.startswith("/api/v1/uploads/"):
        raise RuntimeError(f"upload creation: {r.code}")
    digest = hashlib.sha256(data).digest()
    r = api.checked(api.call("PATCH", location, body=data, timeout=120, headers={
        **tus, "Upload-Offset": "0", "Content-Type": "application/offset+octet-stream",
        "Upload-Checksum": "sha256 " + base64.b64encode(digest).decode()}))
    if r.status != 204:
        raise RuntimeError(f"upload part: {r.code}")
    r = api.checked(api.call("POST", f"{location}/completion", {"sha256": digest.hex()}, headers=tus))
    if r.status != 201 or not r.json().get("materialId"):
        raise RuntimeError(f"upload completion: {r.code}")
    return str(r.json()["materialId"])


def material_state(api: Api, material_id: str) -> str:
    r = api.checked(api.call("GET", f"/api/v1/materials/{material_id}"))
    return str(r.json().get("state")) if r.status == 200 else f"unknown ({r.code})"


def _wait_until_processing(api: Api, material: str, lim: Limits) -> str:
    end = time.monotonic() + lim.processing_wait
    state = material_state(api, material)
    while (state in ("uploading", "waiting") or state.startswith("unknown")) and time.monotonic() < end:
        time.sleep(lim.poll_every)
        api.renew_if_due()
        state = material_state(api, material)
    return state


def _ask_at_once(api: Api, campaign_id: str, picks: list[dict], lim: Limits,
                 when_all_asked: Callable[[], None]) -> list[dict]:
    """Asks every pick at the same moment, one thread each; calls `when_all_asked` once every turn exists."""
    results: list[dict | None] = [None] * len(picks)
    start = threading.Barrier(len(picks))
    asked = threading.Semaphore(0)

    def one(i: int) -> None:
        try:
            start.wait(timeout=30)
        except threading.BrokenBarrierError:
            pass
        try:
            results[i] = run_question(api, campaign_id, picks[i], lim, check_phrases=False, on_created=asked.release)
        except SessionStopped as e:
            results[i] = {"reason": "session.required", "stopped_by": e}
        except Exception as e:  # noqa: BLE001 - one failed burst question must not hide the others
            results[i] = {"reason": f"runner.{type(e).__name__}"}

    threads = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(len(picks))]
    for t in threads:
        t.start()
    for _ in picks:
        asked.acquire(timeout=120)
    when_all_asked()
    for t in threads:
        t.join(lim.question_timeout + 120)
    stop = next((r["stopped_by"] for r in results if r and "stopped_by" in r), None)
    if stop is not None:
        raise stop                                # the session is over: the run stops (burst's finally discards)
    out = []
    for pick, r in zip(picks, results):
        r = r if r and "verdict" in r else {"id": pick["id"], "ended": "none", "verdict": "fail",
                                            "reason": (r or {}).get("reason", "runner.no_result"), "references": []}
        r["done"] = r.get("ended") == "done"
        out.append(r)
    return out


def burst(api: Api, campaign_id: str, questions: list[dict], lim: Limits, stamp: str,
          log: Callable[[str], None]) -> dict:
    """Uploads the generated PDF, fires `burst_size` questions at once while it is processing, waits for the
    answers, then for needs_review or failed, and discards it. Returns the burst record; its status is
    invalid when the material was not processing both before and once the questions were asked."""
    rec: dict = {"status": "invalid", "materialId": None, "stateBefore": None, "stateAfterAsk": None,
                 "questions": [], "discard": None, "finalState": None, "note": None}
    picks = [questions[i * len(questions) // lim.burst_size] for i in range(lim.burst_size)]
    material = None
    try:
        api.renew_if_due()
        material = upload(api, campaign_id, f"sm2-burst-{stamp}.pdf", generated_pdf(lim.burst_pages, stamp))
        rec["materialId"] = material
        log(f"burst: material {material} uploaded, waiting for processing")
        rec["stateBefore"] = _wait_until_processing(api, material, lim)
        if rec["stateBefore"] != "processing":
            rec["note"] = f"the material was {rec['stateBefore']}, not processing, when the burst was due"
            return rec
        api.renew_if_due(force=True)              # a fresh token for the burst's few minutes

        def after_asking() -> None:
            rec["stateAfterAsk"] = material_state(api, material)
            for _ in range(3):                    # a transient failed read is not a verdict
                if not rec["stateAfterAsk"].startswith("unknown"):
                    break
                time.sleep(lim.poll_every)
                rec["stateAfterAsk"] = material_state(api, material)

        rec["questions"] = _ask_at_once(api, campaign_id, picks, lim, after_asking)
        if rec["stateAfterAsk"] != "processing":
            rec["note"] = f"the material was {rec['stateAfterAsk']} once the burst questions were asked"
            return rec
        rec["status"] = "pass" if all(r["done"] for r in rec["questions"]) else "fail"
        return rec
    finally:
        if material:
            rec["finalState"], rec["discard"] = discard(api, material, lim, log)


def discard(api: Api, material_id: str, lim: Limits, log: Callable[[str], None]) -> tuple[str, str]:
    """Waits for needs_review or failed, then discards. Returns (state seen, discard outcome)."""
    end = time.monotonic() + lim.review_wait
    try:
        state = material_state(api, material_id)
        while state not in ("needs_review", "failed", "discarded") and time.monotonic() < end:
            time.sleep(lim.poll_every)
            api.renew_if_due()
            state = material_state(api, material_id)
    except SessionStopped as e:
        state = f"unknown ({e})"
    if state == "discarded":
        return state, "already discarded"
    if state in ("needs_review", "failed"):
        r = api.call("POST", f"/api/v1/materials/{material_id}/discard")
        log(f"burst: material {material_id} {state}, discard HTTP {r.status}")
        outcome = "discarded" if r.status == 200 else f"failed ({r.code})"
    else:
        outcome = "not possible"
    if outcome != "discarded":
        log(f"WARNING burst material {material_id} is {state}, discard {outcome}: discard it in the library "
            "once it needs review")
    return state, outcome


# ------------------------------------------------------------------ release and result

def releases(artifacts: Path, backend_container: str) -> dict:
    """{service: {container, sha, tag}}: the gmshield.sha label (else the image tag) of each running app
    container, and the release whose release.json names that sha (else the sha itself)."""
    out = {}
    for svc in SERVICES:
        name = backend_container.replace("backend", svc) if "backend" in backend_container else f"gmshield-{svc}"
        rc, labels = _inspect(name, "{{json .Config.Labels}}")
        sha = None
        if rc == 0 and labels:
            try:
                sha = (json.loads(labels) or {}).get("gmshield.sha")
            except json.JSONDecodeError:
                sha = None
        if not sha:
            rc2, image = _inspect(name, "{{.Config.Image}}")
            tag = image.rsplit(":", 1)[-1] if rc2 == 0 and ":" in image.rsplit("/", 1)[-1] else ""
            sha = tag if re.fullmatch(r"[0-9a-f]{7,64}", tag) else None
        tag = _release_tag(artifacts / f"GMshield-{svc}" / "releases", sha) if sha else None
        out[svc] = {"container": name, "sha": sha, "tag": tag or sha or "unknown"}
    return out


def _release_tag(releases_dir: Path, sha: str) -> str | None:
    """The newest release whose release.json names this commit (a full sha, or a prefix either way)."""
    found = []
    for rel in releases_dir.glob("*/release.json"):
        try:
            info = json.loads(rel.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        rsha = info.get("sha")
        if isinstance(rsha, str) and rsha and (rsha.startswith(sha) or sha.startswith(rsha)):
            found.append((str(info.get("at", "")), str(info.get("tag") or rel.parent.name)))
    return max(found)[1] if found else None


def gates(questions: list[dict], burst_rec: dict | None, lim: Limits, skipped_burst: bool) -> dict:
    n = len(questions)
    need = math.ceil(lim.pass_share * n)
    passed = sum(1 for q in questions if q.get("verdict") == "pass")
    quick = sum(1 for q in questions if isinstance(q.get("firstWordsMs"), int)
                and q["firstWordsMs"] <= lim.first_words_ms)
    unopened = [{"question": q["id"], "turnId": q.get("turnId"), "number": r.get("number"), "page": r.get("page"),
                 "view": r.get("view"), "picture": r.get("picture")}
                for q in questions + list((burst_rec or {}).get("questions") or [])
                for r in q.get("references") or [] if not r.get("opens")]
    refs = sum(len(q.get("references") or []) for q in questions + list((burst_rec or {}).get("questions") or []))
    if skipped_burst:
        b = {"status": "skipped", "ok": False}
    elif burst_rec is None:
        b = {"status": "not run", "ok": False}
    else:
        done = sum(1 for q in burst_rec.get("questions") or [] if q.get("done"))
        b = {"status": burst_rec["status"], "done": done, "of": lim.burst_size, "ok": burst_rec["status"] == "pass"}
    return {"sourced": {"passed": passed, "of": n, "need": need, "ok": passed >= need},
            "firstWords": {"within": quick, "of": n, "need": need, "limitMs": lim.first_words_ms, "ok": quick >= need},
            "referencesOpen": {"references": refs, "unopened": unopened, "ok": not unopened},
            "burst": b}


def summary_md(res: dict) -> str:
    g = res["gates"]
    rel = res["release"]
    lines = [f"# SM-2 run {res['folder']}", "",
             f"- Status: **{res['status'].upper()}** (exit {res['exitCode']})",
             f"- Started {res['startedAt']}, ended {res['endedAt']}",
             f"- Target: `{res['target']['backendContainer']}` on `{res['target']['network']}`",
             "- Release: " + ", ".join(f"{s} `{rel[s]['tag']}`" for s in SERVICES if s in rel),
             f"- Questions: {res['questionsFile']} (sha256 `{res['questionsSha256'][:12]}`)"]
    if res.get("stoppedBy"):
        lines.append(f"- Stopped early: {res['stoppedBy']}")
    lines += ["", *_gate_table(g), ""]
    if res.get("failuresByReason"):
        lines += ["## Failures by reason", ""] + [f"- {k}: {v}" for k, v in res["failuresByReason"].items()] + [""]
    if g["referencesOpen"]["unopened"]:
        lines += ["## References that did not open", ""]
        lines += [f"- {u['question']} turn `{u['turnId']}` reference {u['number']} page {u['page']}: view "
                  f"{u['view']}, picture {u['picture']}" for u in g["referencesOpen"]["unopened"]] + [""]
    b = res.get("burst")
    if b:
        lines += ["## Burst", "", f"- Material `{b.get('materialId')}`: {b.get('stateBefore')} before, "
                  f"{b.get('stateAfterAsk')} after asking; final {b.get('finalState')}, discard: {b.get('discard')}"]
        if b.get("note"):
            lines.append(f"- {b['note']}")
        lines += [f"- {q['id']}: {q['verdict']}{' (' + str(q['reason']) + ')' if q.get('reason') else ''}, "
                  f"first words {_secs(q.get('firstWordsMs'))}, total {_secs(q.get('totalMs'))}"
                  for q in b.get("questions") or []] + [""]
    lines += ["## Questions", "", "| Id | Lang | Verdict | Reason | First words | Total | Cited pages | Expected |",
              "|---|---|---|---|---|---|---|---|"]
    for q in res["questions"]:
        lines.append(f"| {q['id']} | {q.get('language')} | {q['verdict']} | {q.get('reason') or ''} | "
                     f"{_secs(q.get('firstWordsMs'))} | {_secs(q.get('totalMs'))} | "
                     f"{', '.join(map(str, q.get('citedPages') or []))} | {', '.join(map(str, q['expectedPages']))} |")
    return "\n".join(lines) + "\n"


def _gate_table(g: dict) -> list[str]:
    so, fw, ro, bu = g["sourced"], g["firstWords"], g["referencesOpen"], g["burst"]
    burst = f"{bu['done']}/{bu['of']} ended in done" if "done" in bu else "-"
    return ["| Gate | Result | Measure |", "|---|---|---|",
            f"| Sourced answers (SM-2) | {_verdict(so['ok'])} | {so['passed']}/{so['of']} (need {so['need']}) |",
            f"| First words <= {fw['limitMs'] / 1000:g} s (NFR-14) | {_verdict(fw['ok'])} | "
            f"{fw['within']}/{fw['of']} (need {fw['need']}) |",
            f"| References open | {_verdict(ro['ok'])} | {len(ro['unopened'])} of {ro['references']} did not open |",
            f"| Burst during ingestion (NFR-17) | {bu['status'].upper()} | {burst} |"]


def _verdict(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _secs(ms: int | None) -> str:
    return "-" if ms is None else f"{ms / 1000:.1f} s"


def write_result(root: Path, res: dict) -> Path:
    d = root / res["folder"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "result.json").write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n")
    (d / "summary.md").write_text(summary_md(res))
    return d


# ------------------------------------------------------------------ the command

def say(msg: str) -> None:
    print(msg, flush=True)


def _preflight(api: Api) -> str:
    """Renews the session, then finds the current campaign; refuses while indexing runs or without sources."""
    api.renew_if_due(force=True)
    camp = api.checked(api.call("GET", "/api/v1/campaigns/current"))
    if camp.status != 200 or not camp.json().get("id"):
        raise Refused(f"no current campaign ({camp.code})")
    conv = api.checked(api.call("GET", "/api/v1/conversations/current"))
    cj = conv.json()
    if conv.status != 200:
        raise Refused(f"no current conversation ({conv.code})")
    if cj.get("indexing") is not None:
        raise Refused(f"indexing is still running ({cj['indexing']}): wait until it is done")
    if not cj.get("hasSources"):
        raise Refused("the campaign has no accepted source: upload and accept the SRD first")
    return str(camp.json()["id"])


def _measure(api: Api, campaign_id: str, qs: list[dict], res: dict, lim: Limits, skip_burst: bool,
             stamp: str) -> None:
    """The questions one at a time, then the burst. Fills `res`; a stop is recorded in res["stoppedBy"]."""
    try:
        for i, q in enumerate(qs, 1):
            api.renew_if_due()
            r = run_question(api, campaign_id, q, lim)
            res["questions"].append(r)
            say(f"[{i:>2}/{len(qs)}] {q['id']:<14} {r['verdict']:<4} {r['reason'] or '':<16} first words "
                f"{_secs(r['firstWordsMs'])}, {len(r['references'])} reference(s), pages "
                f"{','.join(map(str, r['citedPages'])) or '-'}")
        if not skip_burst:
            res["burst"] = burst(api, campaign_id, qs, lim, stamp, say)
            say(f"burst: {res['burst']['status']}" + (f" ({res['burst']['note']})" if res["burst"].get("note") else ""))
    except SessionStopped as e:
        res["stoppedBy"] = str(e)
        say(f"sm2: stopped: {e}")
    except KeyboardInterrupt:
        res["stoppedBy"] = "interrupted"
        say("sm2: interrupted; writing the partial result")
    except Exception as e:  # noqa: BLE001 - keep what was measured; the burst's material is discarded in its finally
        res["stoppedBy"] = f"runner error: {type(e).__name__}"
        say(f"sm2: stopped by a runner error: {type(e).__name__}")


def _conclude(res: dict, n_questions: int, lim: Limits, skip_burst: bool) -> None:
    res["gates"] = gates(res["questions"], res["burst"], lim, skip_burst)
    reasons: dict[str, int] = {}
    for q in res["questions"]:
        if q["verdict"] != "pass":
            reasons[str(q["reason"])] = reasons.get(str(q["reason"]), 0) + 1
    res["failuresByReason"] = dict(sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0])))
    complete = res["stoppedBy"] is None and len(res["questions"]) == n_questions
    if not complete:
        res["status"] = "incomplete"
    else:
        res["status"] = "pass" if all(g["ok"] for g in res["gates"].values()) else "fail"
    if res["status"] == "pass":
        res["exitCode"] = EXIT_PASS
    else:
        res["exitCode"] = EXIT_STOPPED if res["stoppedBy"] else EXIT_FAIL


def run(session_file: Path, *, target: Target | None = None, backend_container: str = "gmshield-backend",
        network: str = "gmshield-app", questions_file: Path = QUESTIONS, skip_burst: bool = False,
        lim: Limits | None = None, artifacts: Path | None = None) -> int:
    lim = lim or Limits()
    started = datetime.now(timezone.utc)
    try:
        qs = load_questions(questions_file)
        session = Session(session_file)
        target = target or resolve_target(backend_container, network)
    except (Refused, OSError, json.JSONDecodeError) as e:
        say(f"sm2: cannot start: {e}")
        return EXIT_STOPPED
    if session_file.stat().st_mode & 0o077:
        say(f"sm2: warning: {session_file} is readable by others; it is rewritten with mode 600")
    artifacts = artifacts or load_settings().artifacts
    api = Api(target, session)
    rel = releases(artifacts, target.backend_container)
    res: dict = {"kind": "sm2", "startedAt": started.isoformat(timespec="seconds"),
                 "folder": f"{started:%Y-%m-%d-%H%M%S}-{SAFE_NAME.sub('_', str(rel['backend']['tag']))[:40]}",
                 "target": {"backendContainer": target.backend_container, "network": target.network,
                            "campaignId": None},
                 "release": rel, "questionsFile": str(questions_file),
                 "questionsSha256": hashlib.sha256(questions_file.read_bytes()).hexdigest(),
                 "limits": {"questionTimeoutS": lim.question_timeout, "firstWordsMs": lim.first_words_ms,
                            "passShare": lim.pass_share, "burstSize": lim.burst_size},
                 "questions": [], "burst": None, "stoppedBy": None}
    try:
        campaign_id = _preflight(api)
    except (Refused, SessionStopped) as e:
        say(f"sm2: cannot start: {e}")
        return EXIT_STOPPED
    res["target"]["campaignId"] = campaign_id
    say(f"sm2: {len(qs)} questions, campaign {campaign_id}, release "
        + ", ".join(f"{s} {rel[s]['tag']}" for s in SERVICES))
    _measure(api, campaign_id, qs, res, lim, skip_burst, f"{started:%Y%m%d%H%M%S}")
    _conclude(res, len(qs), lim, skip_burst)
    res["sessionRenewals"] = session.renewals
    res["endedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    d = write_result(artifacts / "quality" / "sm2", res)
    g = res["gates"]
    say(f"sm2: {res['status'].upper()}: sourced {g['sourced']['passed']}/{g['sourced']['of']}, first words "
        f"{g['firstWords']['within']}/{g['firstWords']['of']}, references unopened "
        f"{len(g['referencesOpen']['unopened'])}, burst {g['burst']['status']}")
    say(f"sm2: result in {d}")
    return res["exitCode"]
