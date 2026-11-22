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
passage ids, its references' passage ids, its last event id and how it ended. Never a question's answer or a
passage's text, and no name. Exit status 0 when every step ran (whatever the answers), 2 when the run stopped; the
record then says where (`error`).
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import sys
import time
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
DEFAULT_LIMITS = {"question": 120, "material": 600, "indexing": 600, "poll": 1.0}
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
            return Reply(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, data)
        except (OSError, http.client.HTTPException) as e:
            return Reply(0, {}, json.dumps({"code": f"backend.unreachable ({type(e).__name__})"}).encode())

    def grant(self, g: dict) -> None:
        token = g.get("sessionToken")
        if not isinstance(token, str) or not token:
            raise Stop("the session grant holds no token")
        self.token = token
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

    def record(self) -> dict:
        return {"phase": self.phase, "campaign": self.campaign, "question": self.question, "kind": self.kind,
                "scopeVersion": self.scope_version, "turnId": self.turn_id, "conversationId": self.conversation_id,
                "ended": self.ended, "error": self.error, "stopped": self.stopped, "silent": self.silent,
                "citations": self.citations, "references": self.references, "events": self.events,
                "lastEventId": self.last_event_id, "ms": self.ms}


def ask(api: Api, t: Turn, campaign_id: str, question: str, limit: float) -> Turn:
    """Asks one question in a new questions conversation and follows its events to done or error. Keeps ids and
    codes only: never the answer's text."""
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
        if name == "citation":
            t.citations.append(str(body.get("passageId")))
        elif name == "done":
            t.ended, done = "done", True
            t.stopped, t.silent = bool(body.get("stopped")), bool(body.get("silent"))
            t.references = [[str(i) for i in ref.get("passageIds") or []]
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
                code = Reply(e.code, {}, e.read() if e.fp else b"").code
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

def run(cfg: dict, record: dict) -> None:
    limits = {**DEFAULT_LIMITS, **(cfg.get("limits") or {})}
    clock = Clock(time.monotonic() + float(cfg.get("budget") or 1800))
    api = Api(cfg["base"].rstrip("/"), cfg["credential"])
    timings = record["timings"]
    questions = json.loads(Path(cfg["questions"]).read_text(encoding="utf-8"))
    by_id = {q["id"]: q for q in questions}

    def phase(name: str) -> float:
        record["phase"] = name
        clock.left()
        return time.monotonic()

    t0 = phase("sign_in")
    sign_in(api, cfg["code"], cfg["username"])
    timings["signIn"] = round(time.monotonic() - t0, 1)

    t0 = phase("library")
    places = {"systems": record["systems"], "campaigns": record["campaigns"]}
    for s in cfg["systems"]:
        made = api.expect(api.call("POST", "/api/v1/systems", {"name": s["name"]}), 201, f"system {s['key']}")
        record["systems"][s["key"]] = str(made["id"])
    for c in cfg["campaigns"]:
        made = api.expect(api.call("POST", "/api/v1/campaigns",
                                   {"name": c["name"], "systemId": record["systems"][c["system"]]}), 201,
                          f"campaign {c['key']}")
        record["campaigns"][c["key"]] = str(made["id"])
    for m in cfg["materials"]:
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
                ask(api, t, cid, q["question"], min(limits["question"], clock.left()))
            finally:                                # the turn's id is kept even when the run stops inside it
                record["turns"][-1] = t.record()
    timings["questions"] = round(time.monotonic() - t0, 1)

    t0 = phase("control")
    ctl = cfg["control"]
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
        ask(api, t, cid, q["question"], min(limits["question"], clock.left()))
    finally:
        record["turns"][-1] = t.record()
    off = set_other_tier(api, key, cid, False)
    control["scopeVersionOff"], control["otherTierOff"] = off["version"], off["otherTier"] is False
    timings["control"] = round(time.monotonic() - t0, 1)
    record["renewals"] = api.renewals
    record["phase"] = "complete"


def main(argv: list[str]) -> int:
    cfg = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    record: dict = {"phase": "start", "error": None, "systems": {}, "campaigns": {}, "materials": {}, "scopes": {},
                    "turns": [], "control": None, "timings": {}, "renewals": 0}
    t0 = time.monotonic()
    try:
        run(cfg, record)
    except Stop as e:
        record["error"] = f"{record['phase']}: {e}"
    except Exception as e:  # noqa: BLE001 - recorded by type only: a message could carry a body
        record["error"] = f"{record['phase']}: {type(e).__name__}"
    finally:
        record["timings"]["total"] = round(time.monotonic() - t0, 1)
        out = Path(cfg["out"])
        tmp = out.with_name(out.name + ".tmp")
        tmp.write_text(json.dumps(record, indent=1))
        tmp.replace(out)
    status = "complete" if record["error"] is None else f"stopped at {record['error']}"
    print(f"runner: {status}; {len(record['turns'])} turn(s)", file=sys.stderr, flush=True)
    return 0 if record["error"] is None else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
