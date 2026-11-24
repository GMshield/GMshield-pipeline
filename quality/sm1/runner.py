"""The SM-1 leak test's runner (Story 3.13, part A): a black-box driver of the backend's public API, no browser.

Run by the pipeline (gmshield_ci/leak.py) with the worker image's Python, from a read-only mount, on the test's
internal network, beside the backend in test mode:

    python -I /sm1/runner.py /in/config.json

config.json (written by the pipeline): {"base", "credential", "code", "username", "systems": [{key, name}],
"campaigns": [{key, name, system}], "materials": [{key, file, filename, kind, language, campaign | system}],
"questions", "control": {campaign, question}, "out", "budget", "limits": {question, material, indexing, poll}}.

1. Signs in through the Google stand-in as its own identity (`code` is `stand-in.<sub>.<email>`), as a new account.
2. Builds the library: the systems, the campaigns, then each material uploaded (tus) into its campaign or system,
   processed, accepted, and indexed (each campaign's conversation reports nothing pending).
3. Reads each campaign's scope, which must be at its defaults (campaign and system tiers on, other tier off, model
   knowledge off, no material switched off).
4. Asks every question of `questions` in each campaign, one at a time, each in a new questions conversation, and
   follows its event stream to done or error.
5. The control: turns the other tier of the control campaign on, waits for its indexing, asks the control question,
   then turns the tier off again.

The record (`out`, runner.json) holds ids, counts, codes, scope versions and timings: each turn's id, its citations'
passage ids, its references' passage ids, its last event id and how it ended. From Story 4.3 part C a citation may
name a record (its id is recorded among the citations) and a record reference adds its record's id to its ids.
Never a question's answer or a passage's text, and no name. Exit status 0 when every step ran (whatever the
answers), 2 when the run stopped; the record then says where (`error`).

Part B (Story 3.13, `gmshield_ci sm1`, the real model on roberto-server) runs it in-process through `run_all`, with
these keys besides: "session" ({token, file}: a signed-in GM's session, so there is no sign-in; each renewed token is
written back to the file, mode 600), "suffix" (added to every system and campaign name, " · <suffix>"), "markers"
({material key: [terms]}: each answer's text is read from its delta events in memory, matched, and dropped; only the
terms found are recorded), "pageIds" (each material's passage ids read through the owner-review page view, and from
Story 4.3 part C its record ids, `recordIds`, read from its systems' record lists by the material's name), "delete"
(the run's systems deleted at the end, after a failure too) and no "control". The account's current campaign is put
back as it was before the deletion.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


class Stop(Exception):
    """The run cannot go on: the record says where and why."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow a redirect: the API answers in place
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
DEFAULT_LIMITS = {"question": 120, "material": 600, "indexing": 600, "poll": 1.0, "deletion": 120}
SETTLED = ("needs_review", "ready", "failed", "discarded")


@dataclass
class Reply:
    status: int
    headers: dict
    body: bytes

    def json(self):
        try:
            data = json.loads(self.body or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    @property
    def code(self) -> str:
        """The problem's code (category.reason), else the HTTP status."""
        return str(self.json().get("code") or f"http.{self.status}")


@dataclass
class Clock:
    deadline: float

    def left(self) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Stop("timed out")
        return left


@dataclass
class Api:
    base: str
    credential: str
    token: str = ""
    renew_at: float = 0.0
    renewals: int = 0
    session_file: str = ""             # session given: each renewed token is written back here (mode 600)
    session_given: bool = False        # session given: a refusal that the session ended stops the run at once

    def headers(self, extra: dict | None = None) -> dict:
        h = {"Authorization": f"Bearer {self.credential}", "Accept": "application/json"}
        if self.token:
            h["X-Session-Token"] = self.token
        return {**h, **(extra or {})}

    def open(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None,
             timeout: float = 30.0):
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=self.headers(headers))
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
            return self.ended(path, Reply(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, data))
        except (OSError, http.client.HTTPException) as e:
            return Reply(0, {}, json.dumps({"code": f"backend.unreachable ({type(e).__name__})"}).encode())

    def ended(self, path: str, r: Reply) -> Reply:
        """Session given: a 401 session.* refusal means the GM's session is over, and every later call would be
        refused too, so the run stops at once (the renewal reports its own refusal)."""
        if (self.session_given and r.status == 401 and r.code.startswith("session.")
                and path != "/api/v1/session/renewal"):
            raise Stop(f"the session ended ({r.code})")
        return r

    def grant(self, g: dict) -> None:
        token = g.get("sessionToken")
        if not isinstance(token, str) or not token:
            raise Stop("the session grant holds no token")
        self.token = token
        if self.session_file:
            save_token(Path(self.session_file), token)
        after = g.get("renewAfterSeconds")
        after = after if isinstance(after, int) and after >= 0 else 900
        self.renew_at = time.monotonic() + after * 0.8

    def renew_if_due(self) -> None:
        if not self.token or time.monotonic() < self.renew_at:
            return
        r = self.call("POST", "/api/v1/session/renewal")
        if r.status != 200:
            raise Stop(f"session renewal: {r.code}")
        self.grant(r.json())
        self.renewals += 1

    def expect(self, r: Reply, status: int, what: str) -> dict:
        if r.status != status:
            raise Stop(f"{what}: {r.code}")
        return r.json()


def save_token(path: Path, token: str) -> None:
    """Writes the session token to its file, mode 600, by a rename (never half written)."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


# ------------------------------------------------------------------ the answer's words (part B)

_SPACE = re.compile(r"\s+")
_QUOTES = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u00ad": None})


def normalise(text: str) -> str:
    """Case, accents and whitespace folded: NFKD with the combining marks dropped, casefolded, whitespace collapsed."""
    t = unicodedata.normalize("NFKD", text.translate(_QUOTES))
    t = "".join(c for c in t if not unicodedata.combining(c))
    return _SPACE.sub(" ", t.casefold()).strip()


def markers_in(text: str, markers: dict) -> list[str]:
    """The terms of `markers` ({material key: [terms]}) the text holds, as "KEY:term" (the term as written in
    markers.json). A term matches at the start of a word, so an inflected form ("tripulantes") counts."""
    norm = normalise(text)
    out = []
    for key, terms in markers.items():
        hits = [(normalise(term), term) for term in terms]
        hits = [(n, term) for n, term in hits if n and re.search(r"(?<!\w)" + re.escape(n), norm)]
        # a stem ("tripl") is not named again when a longer term it starts ("triplicado") matched too
        out += [f"{key}:{term}" for n, term in hits if not any(o != n and o.startswith(n) for o, _ in hits)]
    return out


# ------------------------------------------------------------------ sign-in and the library

def sign_in(api: Api, code: str, username: str) -> None:
    started = api.expect(api.call("POST", "/api/v1/sign-in/google"), 200, "sign-in start")
    attempt = started.get("attemptToken")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(str(started.get("authorizationUrl") or "")).query)
    state = (query.get("state") or [""])[0]
    if not attempt or not state:
        raise Stop("sign-in start: no attempt or state")
    outcome = api.expect(api.call("POST", "/api/v1/sign-in/google/callback",
                                  {"attemptToken": attempt, "state": state, "code": code}), 200, "sign-in callback")
    if outcome.get("outcome") == "signed_in":
        api.grant(outcome.get("session") or {})
        return
    grant = api.expect(api.call("POST", "/api/v1/sign-in/complete",
                                {"attemptToken": attempt, "termsAccepted": True, "username": username,
                                 "language": "pt-BR"}), 200, "sign-in completion")
    api.grant(grant)


def upload(api: Api, m: dict, data: bytes, places: dict) -> dict:
    """tus upload of one material into its campaign or system; returns {materialId, versionId}."""
    meta = [("filename", m["filename"]), ("kind", m["kind"]), ("language", m["language"])]
    if m.get("campaign"):
        meta.append(("campaign", places["campaigns"][m["campaign"]]))
    else:
        meta.append(("systems", places["systems"][m["system"]]))
    header = ",".join(f"{k} {base64.b64encode(v.encode()).decode()}" for k, v in meta)
    tus = {"Tus-Resumable": "1.0.0"}
    r = api.call("POST", "/api/v1/uploads", body=b"",
                 headers={**tus, "Upload-Length": str(len(data)), "Upload-Metadata": header})
    location = r.headers.get("location", "")
    if r.status != 201 or not location.startswith("/api/v1/uploads/"):
        raise Stop(f"upload of {m['key']}: {r.code}")
    digest = hashlib.sha256(data).digest()
    r = api.call("PATCH", location, body=data, timeout=120, headers={
        **tus, "Upload-Offset": "0", "Content-Type": "application/offset+octet-stream",
        "Upload-Checksum": "sha256 " + base64.b64encode(digest).decode()})
    if r.status != 204:
        raise Stop(f"upload of {m['key']}: {r.code}")
    done = api.expect(api.call("POST", f"{location}/completion", {"sha256": digest.hex()}, headers=tus), 201,
                      f"upload completion of {m['key']}")
    if not done.get("materialId") or not done.get("versionId"):
        raise Stop(f"upload completion of {m['key']}: no material or version id")
    return {"materialId": str(done["materialId"]), "versionId": str(done["versionId"])}


def material(api: Api, material_id: str) -> dict:
    r = api.call("GET", f"/api/v1/materials/{material_id}")
    return r.json() if r.status == 200 else {"state": f"unknown ({r.code})"}


def wait_state(api: Api, key: str, material_id: str, wanted: tuple[str, ...], limits: dict, clock: Clock) -> str:
    end = time.monotonic() + min(limits["material"], clock.left())
    while True:
        api.renew_if_due()
        m = material(api, material_id)
        state = str(m.get("state"))
        if state in wanted:
            return state
        if state in ("failed", "discarded"):
            raise Stop(f"material {key} {state}: {m.get('failure') or 'no reason'}")
        if time.monotonic() >= end:
            raise Stop(f"material {key} still {state} after {limits['material']}s")
        time.sleep(limits["poll"])


def page_ids(api: Api, key: str, material_id: str) -> list[str]:
    """Every passage id of the material's current version, page by page, through the owner-review page view."""
    ids: list[str] = []
    page, total = 1, 1
    while page <= total:
        api.renew_if_due()
        view = api.expect(api.call("GET", f"/api/v1/materials/{material_id}/pages/{page}?ground=review"), 200,
                          f"page {page} of {key}")
        total = view.get("pageTotal") if isinstance(view.get("pageTotal"), int) else page
        ids += [str(p.get("id")) for p in view.get("passages") or [] if isinstance(p, dict) and p.get("id")]
        page += 1
    return list(dict.fromkeys(ids))


def material_name(api: Api, material_id: str) -> str:
    """The material's name, as its records list names it (never recorded)."""
    api.renew_if_due()
    return str(api.expect(api.call("GET", f"/api/v1/materials/{material_id}"), 200, "material").get("name"))


def record_types(api: Api, system_id: str) -> list[dict]:
    """Every record type of the system (Story 4.4 part B), 50 a page by `offset` until its `total`."""
    found: list[dict] = []
    while True:
        api.renew_if_due()
        path = f"/api/v1/systems/{system_id}/record-types?limit=50&offset={len(found)}"
        page = api.expect(api.call("GET", path), 200, "record types")
        rows = [kind for kind in page.get("items") or [] if isinstance(kind, dict)]
        found += rows
        total = page.get("total") if isinstance(page.get("total"), int) else 0
        if not rows or len(found) >= total:
            return found


def record_ids(api: Api, system_ids: list[str]) -> dict[str, list[str]]:
    """{material name: its record ids} (Story 4.3 part C): every record of the systems' record types (each system's
    records list holds the records of its materials and of its campaigns' materials), by the material it names. Story
    4.4 part B: a system may have more than 50 record types (the core ones and those the GM approved), so its list is
    read page by page (`offset`, up to its `total`)."""
    out: dict[str, list[str]] = {}
    for sid in system_ids:
        for kind in record_types(api, sid):
            if not isinstance(kind, dict) or not kind.get("id"):
                continue
            offset = 0
            while True:
                api.renew_if_due()
                path = f"/api/v1/record-types/{kind['id']}/records?limit=50&offset={offset}"
                page = api.expect(api.call("GET", path), 200, "records")
                rows = [r for r in page.get("items") or [] if isinstance(r, dict) and r.get("id")]
                for r in rows:
                    out.setdefault(str(r.get("materialName")), []).append(str(r["id"]))
                offset += len(rows)
                total = page.get("total") if isinstance(page.get("total"), int) else 0
                if not rows or offset >= total:
                    break
    return out


def choose(api: Api, campaign_id: str) -> None:
    api.expect(api.call("PUT", "/api/v1/campaigns/current", {"campaignId": campaign_id}), 200, "campaign choice")


def wait_indexed(api: Api, key: str, campaign_id: str, limits: dict, clock: Clock) -> float:
    """Until the campaign's conversation reports nothing in scope pending; the seconds it took."""
    t0 = time.monotonic()
    end = t0 + min(limits["indexing"], clock.left())
    choose(api, campaign_id)
    while True:
        api.renew_if_due()
        c = api.expect(api.call("GET", "/api/v1/conversations/current"), 200, f"indexing of {key}")
        failed = c.get("indexingFailed")
        if str(c.get("campaignId")) != campaign_id:
            raise Stop(f"indexing of {key}: another campaign is current")
        if failed and not failed.get("retrying"):
            raise Stop(f"indexing of {key}: {failed.get('passages')} passage(s) failed")
        if c.get("hasSources") and c.get("indexing") is None and not failed:
            return round(time.monotonic() - t0, 1)
        if time.monotonic() >= end:
            raise Stop(f"indexing of {key} not done after {limits['indexing']}s")
        time.sleep(limits["poll"])


def read_scope(api: Api, key: str, campaign_id: str) -> dict:
    s = api.expect(api.call("GET", f"/api/v1/campaigns/{campaign_id}/scope"), 200, f"scope of {key}")
    return {"version": s.get("version"), "campaignTier": s.get("campaignTier"), "systemTier": s.get("systemTier"),
            "otherTier": s.get("otherTier"), "modelKnowledge": s.get("modelKnowledge"),
            "materials": [{"id": str(m.get("id")), "tier": m.get("tier"), "on": m.get("on")}
                          for m in s.get("materials") or [] if isinstance(m, dict)]}


def at_defaults(scope: dict) -> bool:
    return (scope["campaignTier"] is True and scope["systemTier"] is True and scope["otherTier"] is False
            and scope["modelKnowledge"] is False and all(m["on"] is True for m in scope["materials"]))


def set_other_tier(api: Api, key: str, campaign_id: str, on: bool) -> dict:
    s = read_scope(api, key, campaign_id)
    change = {"version": s["version"], "campaignTier": s["campaignTier"], "systemTier": s["systemTier"],
              "otherTier": on, "modelKnowledge": s["modelKnowledge"],
              "materialsOff": [m["id"] for m in s["materials"] if m["on"] is False]}
    api.expect(api.call("PUT", f"/api/v1/campaigns/{campaign_id}/scope", change), 200, f"scope change of {key}")
    after = read_scope(api, key, campaign_id)
    if after["otherTier"] is not on:
        raise Stop(f"scope change of {key}: the other tier is still {'off' if on else 'on'}")
    return after


# ------------------------------------------------------------------ one question

def sse_events(resp, on_event, deadline: float) -> bool:
    """Reads one SSE response; calls on_event(name, data, id) per event. True when on_event asked to stop."""
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
        k, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if k == "event":
            name = value
        elif k == "data":
            data.append(value)
        elif k == "id":
            ev_id = value
    return False


@dataclass
class Turn:
    phase: str
    campaign: str
    question: str
    kind: str
    scope_version: int | None
    turn_id: str | None = None
    conversation_id: str | None = None
    ended: str = "ask"                 # done | error | timeout | ask (the turn was never made)
    error: str | None = None
    stopped: bool = False
    silent: bool = False
    citations: list = field(default_factory=list)
    references: list = field(default_factory=list)
    events: int = 0
    last_event_id: str | None = None
    ms: int | None = None
    markers: list | None = None        # part B: the library terms the answer's text holds (never the text)

    def record(self) -> dict:
        return {"phase": self.phase, "campaign": self.campaign, "question": self.question, "kind": self.kind,
                "scopeVersion": self.scope_version, "turnId": self.turn_id, "conversationId": self.conversation_id,
                "ended": self.ended, "error": self.error, "stopped": self.stopped, "silent": self.silent,
                "citations": self.citations, "references": self.references, "events": self.events,
                "lastEventId": self.last_event_id, "ms": self.ms, "markers": self.markers}


def ask(api: Api, t: Turn, campaign_id: str, question: str, limit: float, markers: dict | None = None) -> Turn:
    """Asks one question in a new questions conversation and follows its events to done or error. Keeps ids and
    codes only: never the answer's text. With `markers`, the text of the delta events is held in memory until the
    turn ends, then only the terms it holds are kept (`t.markers`) and the text is dropped."""
    words: list[str] = []
    try:
        return _ask(api, t, campaign_id, question, limit, words if markers is not None else None)
    finally:
        if markers is not None:
            t.markers = markers_in("".join(words), markers)
        words.clear()


def _ask(api: Api, t: Turn, campaign_id: str, question: str, limit: float, words: list | None) -> Turn:
    api.renew_if_due()
    t0 = time.monotonic()
    r = api.call("POST", f"/api/v1/campaigns/{campaign_id}/turns", {"question": question, "area": "questions"})
    if r.status != 201 or not r.json().get("id"):
        t.error = f"ask:{r.code}"
        return t
    t.turn_id = str(r.json()["id"])
    t.conversation_id = str(r.json().get("conversationId") or "") or None
    deadline = t0 + limit
    done = False

    def on_event(name: str, data: str, ev_id: str | None) -> bool:
        nonlocal done
        t.events += 1
        if ev_id:
            t.last_event_id = ev_id
        try:
            body = json.loads(data)
        except ValueError:
            body = {}
        body = body if isinstance(body, dict) else {}
        if name == "delta" and words is not None and isinstance(body.get("text"), str):
            words.append(body["text"])
        elif name == "citation":
            # Story 4.3 part C: a citation names a passage or a record.
            t.citations.append(str(body.get("recordId") or body.get("passageId")))
        elif name == "done":
            t.ended, done = "done", True
            t.stopped, t.silent = bool(body.get("stopped")), bool(body.get("silent"))
            t.references = [[str(i) for i in ref.get("passageIds") or []]
                            + ([str(ref["recordId"])] if ref.get("recordId") else [])
                            for ref in body.get("references") or [] if isinstance(ref, dict)]
            return True
        elif name == "error":
            t.ended, done = "error", True
            t.error = str(body.get("code") or "error")
            return True
        return False

    while not done:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        extra = {"Accept": "text/event-stream"}
        if t.last_event_id:
            extra["Last-Event-ID"] = t.last_event_id
        try:
            with api.open("GET", f"/api/v1/turns/{t.turn_id}/events", headers=extra, timeout=min(30.0, left)) as resp:
                sse_events(resp, on_event, deadline)
        except urllib.error.HTTPError as e:
            with e:
                code = api.ended(f"/api/v1/turns/{t.turn_id}/events", Reply(e.code, {}, e.read() if e.fp else b"")).code
            if e.code < 500:
                t.ended, t.error = "error", f"events:{code}"
                break
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
        except (OSError, http.client.HTTPException):    # a read timeout or a cut stream: reopen after the last event
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
    if not done and t.ended == "ask":
        t.ended, t.error = "timeout", "timeout"
        api.call("POST", f"/api/v1/turns/{t.turn_id}/stop")
    t.ms = round((time.monotonic() - t0) * 1000)
    return t


# ------------------------------------------------------------------ the run

def new_record() -> dict:
    return {"phase": "start", "error": None, "systems": {}, "campaigns": {}, "materials": {}, "scopes": {},
            "turns": [], "control": None, "timings": {}, "renewals": 0}


def make_api(cfg: dict) -> Api:
    """The API client: signed out (part A signs in), or holding the given session (part B)."""
    api = Api(cfg["base"].rstrip("/"), cfg["credential"])
    session = cfg.get("session")
    if session:
        api.token, api.session_file = str(session["token"]), str(session.get("file") or "")
        api.session_given = True
    return api


def named(name: str, suffix: str | None) -> str:
    return f"{name} · {suffix}" if suffix else name


def current_campaign(api: Api) -> tuple[str | None, str | None]:
    """(the account's current campaign, None), (None, None) when it has none (404), or (None, the refusal's code)
    when it could not be read: the run then cannot put it back."""
    r = api.call("GET", "/api/v1/campaigns/current")
    if r.status == 200 and r.json().get("id"):
        return str(r.json()["id"]), None
    return None, None if r.status == 404 else r.code


def run(cfg: dict, record: dict, api: Api | None = None) -> None:
    limits = {**DEFAULT_LIMITS, **(cfg.get("limits") or {})}
    clock = Clock(time.monotonic() + float(cfg.get("budget") or 1800))
    api = api or make_api(cfg)
    timings = record["timings"]
    questions = json.loads(Path(cfg["questions"]).read_text(encoding="utf-8"))
    by_id = {q["id"]: q for q in questions}
    suffix, markers = cfg.get("suffix"), cfg.get("markers")

    def phase(name: str) -> float:
        record["phase"] = name
        clock.left()
        return time.monotonic()

    if api.token:                                   # session given: the GM is signed in already
        t0 = phase("session")
        api.renew_if_due()
        record["previousCurrent"], error = current_campaign(api)
        if error:
            record["previousCurrentError"] = error
        timings["session"] = round(time.monotonic() - t0, 1)
    else:
        t0 = phase("sign_in")
        sign_in(api, cfg["code"], cfg["username"])
        timings["signIn"] = round(time.monotonic() - t0, 1)

    t0 = phase("library")
    places = {"systems": record["systems"], "campaigns": record["campaigns"]}
    for s in cfg["systems"]:
        api.renew_if_due()
        made = api.expect(api.call("POST", "/api/v1/systems", {"name": named(s["name"], suffix)}), 201,
                          f"system {s['key']}")
        record["systems"][s["key"]] = str(made["id"])
    for c in cfg["campaigns"]:
        api.renew_if_due()
        made = api.expect(api.call("POST", "/api/v1/campaigns",
                                   {"name": named(c["name"], suffix), "systemId": record["systems"][c["system"]]}),
                          201, f"campaign {c['key']}")
        record["campaigns"][c["key"]] = str(made["id"])
    for m in cfg["materials"]:
        api.renew_if_due()
        record["materials"][m["key"]] = upload(api, m, Path(m["file"]).read_bytes(), places)
    timings["library"] = round(time.monotonic() - t0, 1)

    t0 = phase("processing")
    for m in cfg["materials"]:
        rec = record["materials"][m["key"]]
        wait_state(api, m["key"], rec["materialId"], ("needs_review", "ready"), limits, clock)
        api.renew_if_due()
        api.expect(api.call("POST", f"/api/v1/materials/{rec['materialId']}/accept"), 200, f"accept of {m['key']}")
        rec["state"] = wait_state(api, m["key"], rec["materialId"], ("ready",), limits, clock)
    timings["processing"] = round(time.monotonic() - t0, 1)

    t0 = phase("indexing")
    for key, cid in record["campaigns"].items():
        timings[f"indexing.{key}"] = wait_indexed(api, key, cid, limits, clock)
        scope = read_scope(api, key, cid)
        record["scopes"][key] = scope
        if not at_defaults(scope):
            raise Stop(f"the scope of {key} is not at its defaults")
    timings["indexing"] = round(time.monotonic() - t0, 1)

    t0 = phase("questions")
    for q in questions:
        for key, cid in record["campaigns"].items():
            t = Turn("main", key, q["id"], q["kind"], record["scopes"][key]["version"])
            record["turns"].append(t.record())
            try:
                ask(api, t, cid, q["question"], min(limits["question"], clock.left()), markers)
            finally:                                # the turn's id is kept even when the run stops inside it
                record["turns"][-1] = t.record()
    timings["questions"] = round(time.monotonic() - t0, 1)

    ctl = cfg.get("control")
    if ctl:
        t0 = phase("control")
        key, cid = ctl["campaign"], record["campaigns"][ctl["campaign"]]
        control = record["control"] = {"campaign": key, "question": ctl["question"], "scopeVersionOn": None,
                                       "scopeVersionOff": None, "otherTierOff": False}
        on = set_other_tier(api, key, cid, True)
        control["scopeVersionOn"] = on["version"]
        timings["indexing.control"] = wait_indexed(api, key, cid, limits, clock)
        q = by_id[ctl["question"]]
        t = Turn("control", key, q["id"], q["kind"], on["version"])
        record["turns"].append(t.record())
        try:
            ask(api, t, cid, q["question"], min(limits["question"], clock.left()), markers)
        finally:
            record["turns"][-1] = t.record()
        off = set_other_tier(api, key, cid, False)
        control["scopeVersionOff"], control["otherTierOff"] = off["version"], off["otherTier"] is False
        timings["control"] = round(time.monotonic() - t0, 1)
    record["renewals"] = api.renewals
    record["phase"] = "complete"


def _reason(e: BaseException) -> str:
    """A step's failure as recorded: a Stop's own words (codes and keys only), else the exception's type only."""
    return str(e) if isinstance(e, Stop) else type(e).__name__


def run_all(cfg: dict, record: dict, api: Api | None = None) -> None:
    """`run`, then, whatever happened (a stop, an error, Ctrl-C): the account's current campaign put back (part B),
    each material's passage ids read (`pageIds`), and the run's systems deleted (`delete`) or kept. Every failure is
    recorded in `record`, never raised."""
    api = api or make_api(cfg)
    t0 = time.monotonic()
    try:
        run(cfg, record, api)
    except Stop as e:
        record["error"] = f"{record['phase']}: {e}"
    except KeyboardInterrupt:
        record["error"] = f"{record['phase']}: interrupted"
    except Exception as e:  # noqa: BLE001 - recorded by type only: a message could carry a body
        record["error"] = f"{record['phase']}: {type(e).__name__}"
    finally:
        limits = {**DEFAULT_LIMITS, **(cfg.get("limits") or {})}
        try:
            finish(cfg, record, api, limits)
        finally:
            record["renewals"] = api.renewals
            record["timings"]["total"] = round(time.monotonic() - t0, 1)


def finish(cfg: dict, record: dict, api: Api, limits: dict) -> None:
    if record.get("previousCurrent"):
        try:
            api.renew_if_due()
            r = api.call("PUT", "/api/v1/campaigns/current", {"campaignId": record["previousCurrent"]})
            record["currentRestored"] = True if r.status == 200 else r.code
        except Exception as e:  # noqa: BLE001 - the deletion must still run
            record["currentRestored"] = _reason(e)
    if cfg.get("pageIds"):
        for key, m in record["materials"].items():
            try:
                m["passageIds"] = page_ids(api, key, m["materialId"])
            except Exception as e:  # noqa: BLE001 - recorded; the deletion must still run
                m["passageIdsError"] = _reason(e)
        try:
            by_name = record_ids(api, list(record["systems"].values()))
            for key, m in record["materials"].items():
                m["recordIds"] = by_name.get(material_name(api, m["materialId"]), [])
        except Exception as e:  # noqa: BLE001 - recorded; the deletion must still run
            record["recordIdsError"] = _reason(e)
    if record["systems"]:
        if cfg.get("delete"):
            record["deletion"] = delete_library(api, record, limits)
        else:
            record["deletion"] = {"kept": True, "systems": [{"key": k, "id": v, "delete": None, "gone": False}
                                                            for k, v in record["systems"].items()]}


def delete_library(api: Api, record: dict, limits: dict) -> dict:
    """Deletes each of the run's systems (Story 3.1 part B: its campaigns, their conversations and its materials go
    with it), then polls its deletion preview until the system is not found. `delete`: started (202), not_found (404:
    already deleting or gone) or the refusal's code; `gone`: the preview answered not found."""
    out: dict = {"kept": False, "systems": [], "startedAt": time.time()}
    for key, sid in record["systems"].items():
        item: dict = {"key": key, "id": sid, "delete": None, "gone": False}
        out["systems"].append(item)
        try:
            api.renew_if_due()
            r = api.call("DELETE", f"/api/v1/systems/{sid}")
            item["delete"] = {202: "started", 404: "not_found"}.get(r.status, r.code)
            if r.status not in (202, 404):
                continue
            end = time.monotonic() + float(limits["deletion"])
            while True:
                api.renew_if_due()
                if api.call("GET", f"/api/v1/systems/{sid}/deletion").status == 404:
                    item["gone"] = True
                    break
                if time.monotonic() >= end:
                    break
                time.sleep(limits["poll"])
        except Exception as e:  # noqa: BLE001 - the other system must still be deleted
            item["error"] = _reason(e)
    return out


def main(argv: list[str]) -> int:
    cfg = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    record = new_record()
    try:
        run_all(cfg, record)
    finally:
        out = Path(cfg["out"])
        tmp = out.with_name(out.name + ".tmp")
        tmp.write_text(json.dumps(record, indent=1))
        tmp.replace(out)
    status = "complete" if record["error"] is None else f"stopped at {record['error']}"
    print(f"runner: {status}; {len(record['turns'])} turn(s)", file=sys.stderr, flush=True)
    return 0 if record["error"] is None else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
