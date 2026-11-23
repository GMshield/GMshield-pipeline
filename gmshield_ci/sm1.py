"""SM-1 with the real model (Story 3.13, part B): two campaigns of one system never leak, on the deployed stack.

Run on roberto-server, in ~/gmshield-ci/runner, after a browser sign-in whose session token is saved (mode 600):

    python3 -m gmshield_ci sm1 --session-file ~/.config/gmshield/sm1-session

As the signed-in GM, through the backend's public API (quality/sm1/runner.py, in-process, in its session-given mode),
it builds part A's library under run-suffixed names ("Vale de Ferro · sm1 2026-11-23 0130"): system "Vale de Ferro"
with its rulebook `R`, its campaigns "Casa" (house rules `HA`) and "Livro" (by-the-book session notes `NB`), and a
second system "Mar de Cinzas" with its rulebook `X`, the same PDFs as part A (`leak.library_pdf`). Scopes stay at
their defaults (other tier off, model knowledge off), so the account's other systems are in the off "other" tier.
It asks the 40 questions of quality/sm1/questions.json in both campaigns, one at a time, each in a new questions
conversation, with the real model. Then it reads each material's passage ids through the owner-review page view and
deletes the run's two systems (Story 3.1 part B: their campaigns, materials and conversations go with them), after a
failure too, unless `--keep`.

The six checks; any failure fails the run:
1. found and fetched: the ids of each turn's `retrieval.search_done` lines in the worker's log (the job matched to the
   turn through the backend's `conversation.history_read` line) stay inside its campaign's allowed set;
2. cited: every citation id and every reference id is inside it;
3. clean ends: every turn ends in done; scope.passage_refused is a found leak; other errors are counted by code, and
   more than `max_errors` (4) of 80 fail the run (rate limits may refuse a few);
4. not restated: no Livro answer holds an HA marker or house-only phrase, no Casa answer an NB marker, neither an X
   marker (quality/sm1/markers.json; case, accents and whitespace folded);
5. the by-the-book campaign never mentions the house rule: check 4 for Livro and HA, on its own line;
6. not empty: at least 20 of Casa's 24 house answers cite HA, and at least 6 of Livro's 8 notes answers cite NB.

Exit status: 0 when every check passes, 1 when one fails (or a pipeline run holds the poll lock: nothing is made),
2 when the run cannot start (no session, no target, a refused renewal: nothing is made) or stopped before every
question was asked. The result goes to ~/gmshield-ci/artifacts/quality/sm1/<UTC yyyy-mm-dd-HHMMSS>-<backend
release>/ as result.json and summary.md: ids, verdicts, the library terms found, error codes and timings. No answer
or passage text reaches the result, standard output or a log: the runner reads each answer's text from its delta
events in memory, keeps only the terms it holds, and drops it. The bearer credential is read from the backend
container's environment and never printed; the session token lives only in the session file, rewritten (mode 600)
after each renewal. Standard library only, and no model call of its own.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import signal
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import leak, sm2
from .config import Settings, load_settings
from .dockerops import capture
from .sm2 import Refused, Session, Target

QUALITY = leak.QUALITY
MARKERS = QUALITY / "markers.json"
QUESTIONS = leak.QUESTIONS
EXIT_PASS, EXIT_FAIL, EXIT_STOPPED = 0, 1, 2
CHECKS = ("found", "cited", "ended", "restated", "houseRuleInLivro", "notEmpty")
SIGN_IN_HELP = ("sign in to GMshield in the browser, then save the session cookie's token (the part before the last "
                "'.') in {file}, mode 600")


@dataclass
class Limits:
    """The run's limits; tests shrink the waits."""
    question: float = 300.0            # no done within this many seconds: the turn is stopped (as sm2)
    material: float = 1800.0           # each material reaching needs_review, then ready
    indexing: float = 1800.0           # each campaign's sources indexed
    poll: float = 2.0
    budget: float = 6 * 3600.0         # the whole library and question phase
    deletion: float = 120.0            # each system's deletion preview answering not found
    deleted_wait: float = 900.0        # the backend logging library.system_deleted for each (a sweep every 10 min)
    log_every: float = 5.0
    max_errors: int = 4                # turns that may end in an error other than scope.passage_refused
    house_cite_ha: int = 20            # of Casa's 24 house answers
    notes_cite_nb: int = 6             # of Livro's 8 notes answers


RUNNER_MODULE = "gmshield_ci_sm1_runner"           # not tests/test_leak.py's "sm1_runner"
LOG_LOOKBACK = timedelta(minutes=10)              # logs are read from this long before the run's start


def load_runner():
    """quality/sm1/runner.py as a module (it is a standalone script, not a package), loaded once and only when an
    sm1 run needs it, so a broken runner never breaks the other commands (poll among them)."""
    mod = sys.modules.get(RUNNER_MODULE)
    if mod is None:
        spec = importlib.util.spec_from_file_location(RUNNER_MODULE, QUALITY / "runner.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod              # its dataclasses look their module up
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            del sys.modules[spec.name]
            raise
    return mod


def load_markers(path: Path = MARKERS) -> dict:
    """{"terms": {material: [every marker, phrase and translation]}, "forbidden": {campaign: [material]}}."""
    data = json.loads(path.read_text(encoding="utf-8"))
    terms = {key: list(m.get("markers") or []) + list(m.get("phrases") or []) + list(m.get("translations") or [])
             for key, m in data["materials"].items()}
    return {"terms": terms, "forbidden": {c: list(v) for c, v in data["forbidden"].items()}}


# ------------------------------------------------------------------ the apps' logs

def container_log(container: str, since: str) -> str | None:
    """`docker logs --timestamps --since` of a container (its standard output, where both apps write every line but
    errors), or None when it cannot be read. Held in memory only: the apps log ids, counts and codes, and nothing of
    it is written."""
    try:
        rc, out = capture(["docker", "logs", "--timestamps", "--since", since, container], timeout=300)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return out if rc == 0 else None


def oldest_line(log_text: str | None) -> datetime | None:
    """The time of the log's first line (`docker logs --timestamps`' prefix), or None."""
    for line in (log_text or "").splitlines():
        try:
            return datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def log_state(log_text: str | None, started: datetime) -> dict:
    """Whether the log was read and, when its oldest line is later than the run's start although it was read from
    LOG_LOOKBACK before it, that it is possibly truncated (production rotates logs at 3 x 10 MB)."""
    oldest = oldest_line(log_text)
    return {"read": log_text is not None, "oldest": oldest.isoformat() if oldest else None,
            "possiblyTruncated": oldest is not None and oldest > started}


def jobs_of_turns(backend_log: str) -> dict[str, str]:
    """{job id: turn id}, from the backend's conversation.history_read lines (one per input read of an answer job)."""
    return {str(d["jobId"]): str(d["turnId"])
            for d in leak.log_events(backend_log, "conversation.history_read") if d.get("jobId") and d.get("turnId")}


def deleted_systems(backend_log: str) -> set[str]:
    """The system ids of the backend's library.system_deleted lines: their recorded deletion finished."""
    return {str(d["systemId"]) for d in leak.log_events(backend_log, "library.system_deleted")
            if d.get("systemId")}


def app_container(backend_container: str, service: str) -> str:
    """The worker (or frontend) beside the backend: gmshield-worker for production, gm27-worker for a develop stack."""
    return backend_container.replace("backend", service) if "backend" in backend_container else f"gmshield-{service}"


# ------------------------------------------------------------------ the checks (pure)

def judge(record: dict, job_turn: dict[str, str] | None, found: dict[str, set[str]] | None, markers: dict,
          lim: Limits, asked: list[dict] | None = None) -> dict:
    """The six checks over the runner's record (with each material's page-view passage ids), the backend log's
    job-to-turn map and the worker log's found ids (None: that log could not be read). Ids, counts, codes and the
    library terms found: the record holds no text, and none is added."""
    asked = asked if asked is not None else leak.questions()
    materials = {k: m for k, m in (record.get("materials") or {}).items() if isinstance(m, dict)}
    # Story 4.3 part C: a record id stands for its material as a passage id does (the runner's `recordIds`).
    material_of = {str(p): key for key, m in materials.items()
                   for p in [*(m.get("passageIds") or []), *(m.get("recordIds") or [])]}
    unread = sorted(k for k, m in materials.items() if "passageIds" not in m)
    # the record ids unread (Story 4.3 part C): a cited or found record would look foreign, whatever its material
    records_unread = record.get("recordIdsError") is not None
    # an allowed material's ids unread: its ids would look foreign, so found and cited cannot be checked at all
    blind = [k for k in unread if any(k in keys for keys in leak.ALLOWED.values())]
    unreadable = ([f"passage ids unread: {', '.join(unread)}"] if unread else []) + (
        ["record ids unread: every material"] if records_unread else [])

    def foreign(ids) -> list[dict]:
        return [{"id": p, "material": material_of.get(p, "unknown")} for p in sorted(ids)]

    allowed = {c: {p for p, k in material_of.items() if k in keys} for c, keys in leak.ALLOWED.items()}
    turns_of: dict[str, list[str]] = {}
    for job, tid in (job_turn or {}).items():
        turns_of.setdefault(tid, []).append(job)
    failures: list[dict] = []
    unchecked: list[dict] = []                    # done turns whose found ids the logs do not show
    errors: Counter = Counter()
    rows = []
    turns = [t for t in record.get("turns") or [] if isinstance(t, dict) and t.get("phase") == "main"]
    for t in turns:
        if t.get("ended") == "ask" and not t.get("turnId") and not t.get("error"):
            continue                # never made: the runner stopped before posting it, and its error says why
        camp, qid = t.get("campaign"), t.get("question")
        name = leak.NAMES.get(camp, str(camp))
        ok_ids = allowed.get(camp, set())
        here: list[dict] = []

        def fail(check: str, **extra) -> None:
            item = {"check": check, "campaign": name, "question": qid, **extra}
            here.append(item)
            failures.append(item)

        ended, error = t.get("ended"), t.get("error")
        # 1. found and fetched, from the worker's own record of the turn's jobs
        jobs = sorted(turns_of.get(str(t.get("turnId")), []))
        got: set[str] | None = None
        if found is not None and job_turn is not None:
            seen = [found[j] for j in jobs if j in found]
            got = set().union(*seen) if seen else None
            if got and got - ok_ids and not blind and not records_unread:
                fail("found", jobs=jobs, foreign=foreign(got - ok_ids))
            elif got is None and ended == "done":
                unchecked.append({"campaign": name, "question": qid, "jobs": jobs,
                                  "code": "no search_done line" if jobs else "no history_read line"})
        if error == "scope.passage_refused":
            fail("found", jobs=jobs, code=error)
        # 2. cited: the citation events as relayed, and the done event's references
        cited = {str(p) for p in t.get("citations") or []} | {str(p) for ref in t.get("references") or [] for p in ref}
        if cited - ok_ids and not blind and not records_unread:
            fail("cited", foreign=foreign(cited - ok_ids))
        cites = sorted({material_of[p] for p in cited & ok_ids})
        # 3. clean ends: counted by code
        code = None
        if error != "scope.passage_refused":
            if ended != "done" or error:
                code = str(error or ended or "unknown")
            elif t.get("stopped"):
                code = "stopped"
        if code:
            errors[code] += 1
        # 4 and 5. not restated
        terms = list(t.get("markers") or [])
        bad = [m for m in terms if m.split(":", 1)[0] in markers["forbidden"].get(camp, [])]
        if bad:
            fail("restated", markers=bad)
            if camp == "livro" and any(m.startswith("HA:") for m in bad):
                fail("houseRuleInLivro", markers=[m for m in bad if m.startswith("HA:")])
        rows.append({"campaign": name, "question": qid, "kind": t.get("kind"), "turnId": t.get("turnId"),
                     "jobIds": jobs, "ended": ended, "error": error, "stopped": bool(t.get("stopped")),
                     "silent": bool(t.get("silent")), "found": len(got) if got is not None else None,
                     "cited": len(cited), "cites": cites, "markers": terms, "ms": t.get("ms"),
                     "clean": not here and code is None, "failed": sorted({f["check"] for f in here})})

    def cite_count(campaign: str, kind: str, key: str) -> tuple[int, int]:
        mine = [r for r in rows if r["campaign"] == leak.NAMES[campaign] and r["kind"] == kind]
        return sum(1 for r in mine if key in r["cites"]), sum(1 for q in asked if q.get("kind") == kind)

    house, house_of = cite_count("casa", "house", "HA")
    notes, notes_of = cite_count("livro", "notes", "NB")
    expected = len(asked) * len(leak.ALLOWED)

    def of(check: str) -> list[dict]:
        return [f for f in failures if f["check"] == check]

    logs_ok = found is not None and job_turn is not None
    why_found = ([] if logs_ok else ["worker or backend log unreadable"]) + (
        [f"passage ids unread: {', '.join(blind)}"] if blind else []) + (
        ["record ids unread: every material"] if records_unread else []) + (
        [f"{len(unchecked)} done turn(s) not in the logs, first {unchecked[0]['campaign']} "
         f"{unchecked[0]['question']}: {unchecked[0]['code']}"] if unchecked else [])
    checks = {
        "found": {"ok": not why_found and not of("found"), "failures": of("found"), "unchecked": unchecked,
                  **({"code": "; ".join(why_found)} if why_found else {})},
        "cited": {"ok": not unreadable and not of("cited"), "failures": of("cited"),
                  **({"code": "; ".join(unreadable)} if unreadable else {})},
        "ended": {"ok": sum(errors.values()) <= lim.max_errors, "done": sum(1 for r in rows if r["ended"] == "done"),
                  "errors": dict(sorted(errors.items(), key=lambda kv: (-kv[1], kv[0]))),
                  "errorCount": sum(errors.values()), "max": lim.max_errors},
        "restated": {"ok": not of("restated"), "failures": of("restated")},
        "houseRuleInLivro": {"ok": not of("houseRuleInLivro"), "failures": of("houseRuleInLivro")},
        "notEmpty": {"ok": house >= lim.house_cite_ha and notes >= lim.notes_cite_nb,
                     "casaHouseCiteHA": house, "casaHouseOf": house_of, "needHA": lim.house_cite_ha,
                     "livroNotesCiteNB": notes, "livroNotesOf": notes_of, "needNB": lim.notes_cite_nb},
    }
    campaigns = {}
    for c, keys in leak.ALLOWED.items():
        mine = [r for r in rows if r["campaign"] == leak.NAMES[c]]
        campaigns[leak.NAMES[c]] = {
            "id": (record.get("campaigns") or {}).get(c), "allowed": list(keys),
            "scopeVersion": ((record.get("scopes") or {}).get(c) or {}).get("version"), "turns": len(mine),
            "clean": sum(1 for r in mine if r["clean"]), "done": sum(1 for r in mine if r["ended"] == "done"),
            "restated": sum(1 for r in mine if "restated" in r["failed"]),
            "cites": dict(Counter(k for r in mine for k in r["cites"]))}
    result = {"questions": len(asked), "expected": expected, "turns": len(rows),
              "clean": sum(1 for r in rows if r["clean"]),
              "restated": sum(1 for r in rows if "restated" in r["failed"]), "campaigns": campaigns,
              "materials": {k: {"materialId": m.get("materialId"), "versionId": m.get("versionId"),
                                "passages": len(m.get("passageIds") or []),
                                "records": len(m.get("recordIds") or []),
                                **({"passageIdsError": m["passageIdsError"]} if m.get("passageIdsError") else {})}
                            for k, m in materials.items()},
              **({"recordIdsError": record["recordIdsError"]} if record.get("recordIdsError") else {}),
              "checks": checks, "turnsDetail": rows}
    result["status"], result["reason"] = _verdict(result, record)
    return result


def _verdict(result: dict, record: dict) -> tuple[str, str]:
    """(pass | fail | incomplete, the first reason). A leak or a restatement fails the run even when it stopped
    early; otherwise a stopped run is incomplete."""
    c = result["checks"]
    for check, word in (("found", "leak found"), ("cited", "leak cited")):
        f = next(iter(c[check]["failures"]), None)
        if f:
            what = leak._named(f["foreign"]) if f.get("foreign") else f.get("code", "")
            return "fail", f"{word}: {f['campaign']} {f['question']} {what}".rstrip()
    f = next(iter(c["restated"]["failures"]), None)
    if f:
        return "fail", f"restated: {f['campaign']} {f['question']} {', '.join(f['markers'])}"
    if record.get("error"):
        return "incomplete", f"the runner stopped at {record['error']}"
    if result["turns"] < result["expected"]:
        return "incomplete", f"only {result['turns']}/{result['expected']} questions asked"
    for check, word in (("found", "found and fetched"), ("cited", "cited")):
        if not c[check]["ok"]:                     # no failure named: the check could not be made
            return "fail", f"cannot check ({word}): {c[check]['code']}"
    e = c["ended"]
    if not e["ok"]:
        codes = ", ".join(f"{k} {v}" for k, v in e["errors"].items())
        return "fail", f"errors: {e['errorCount']} of {result['turns']} turns ({codes}), more than {e['max']}"
    n = c["notEmpty"]
    if not n["ok"]:
        return "fail", (f"not exercised: Casa house answers citing HA {n['casaHouseCiteHA']}/{n['casaHouseOf']} "
                        f"(need {n['needHA']}), Livro notes answers citing NB {n['livroNotesCiteNB']}/"
                        f"{n['livroNotesOf']} (need {n['needNB']})")
    per = ", ".join(f"{name} {v['clean']}/{v['turns']}" for name, v in result["campaigns"].items())
    return "pass", f"{result['clean']}/{result['expected']} clean, {result['restated']} restated ({per})"


# ------------------------------------------------------------------ the result

def deletion_summary(record: dict, finished: set[str]) -> dict:
    d = record.get("deletion") or {"kept": False, "systems": []}
    systems = [{**s, "deleted": s.get("id") in finished} for s in d.get("systems") or []]
    return {"kept": bool(d.get("kept")), "systems": systems,
            "finished": bool(systems) and not d.get("kept") and all(s["deleted"] for s in systems)}


def summary_md(res: dict) -> str:
    rel, r = res["release"], res["result"]
    lines = [f"# SM-1 run with the real model {res['folder']}", "",
             f"- Status: **{res['status'].upper()}** (exit {res['exitCode']}): {res['reason']}",
             f"- Started {res['startedAt']}, ended {res['endedAt']}",
             f"- Target: `{res['target']['backendContainer']}` on `{res['target']['network']}`, worker log of "
             f"`{res['target']['workerContainer']}`",
             "- Release: " + ", ".join(f"{s} `{rel[s]['tag']}`" for s in sm2.SERVICES if s in rel),
             f"- Questions: {res['questionsFile']} (sha256 `{res['questionsSha256'][:12]}`); markers sha256 "
             f"`{res['markersSha256'][:12]}`; names suffixed \"{res['suffix']}\""]
    if res.get("runnerError"):
        lines.append(f"- Stopped early: {res['runnerError']}")
    for app, state in (res.get("logs") or {}).items():
        if not state.get("read"):
            lines.append(f"- The {app} log could not be read")
        elif state.get("possiblyTruncated"):
            lines.append(f"- The {app} log is possibly truncated: its oldest line ({state.get('oldest')}) is later "
                         "than the run's start (logs rotate at 3 x 10 MB)")
    c = r["checks"]
    livro = c["houseRuleInLivro"]["failures"]
    lines += ["", "| Check | Result | Measure |", "|---|---|---|",
              f"| 1. Found and fetched | {_ok(c['found']['ok'])} | {_failures(c['found'])} |",
              f"| 2. Cited | {_ok(c['cited']['ok'])} | {_failures(c['cited'])} |",
              f"| 3. Clean ends | {_ok(c['ended']['ok'])} | {c['ended']['done']} done, {c['ended']['errorCount']} "
              f"error(s) (at most {c['ended']['max']})"
              + (f": {_codes(c['ended']['errors'])}" if c['ended']['errors'] else "") + " |",
              f"| 4. Not restated | {_ok(c['restated']['ok'])} | {len(c['restated']['failures'])} answer(s) restate "
              "a material outside the campaign |",
              f"| 5. Livro never mentions the house rule | {_ok(c['houseRuleInLivro']['ok'])} | "
              + ("no Livro answer holds an HA marker or phrase" if not livro else
                 "; ".join(f"{f['question']} {', '.join(f['markers'])}" for f in livro)) + " |",
              f"| 6. Not empty | {_ok(c['notEmpty']['ok'])} | Casa house answers citing HA "
              f"{c['notEmpty']['casaHouseCiteHA']}/{c['notEmpty']['casaHouseOf']} (need {c['notEmpty']['needHA']}), "
              f"Livro notes answers citing NB {c['notEmpty']['livroNotesCiteNB']}/{c['notEmpty']['livroNotesOf']} "
              f"(need {c['notEmpty']['needNB']}) |", ""]
    lines.append("Livro (by the book): " + ("no answer mentioned the house rule." if not livro else
                 "the house rule was mentioned in " + "; ".join(
                     f"{f['question']} ({', '.join(f['markers'])})" for f in livro) + "."))
    lines.append("")
    if r.get("campaigns"):
        keys = [m["key"] for m in leak.MATERIALS]
        lines += ["| Campaign | Allowed | Turns | Done | Clean | Restated | " + " | ".join(f"Cites {k}" for k in keys)
                  + " |", "|---|---|---|---|---|---|" + "---|" * len(keys)]
        for name, v in r["campaigns"].items():
            lines.append(f"| {name} | {' + '.join(v['allowed'])} | {v['turns']} | {v['done']} | {v['clean']} | "
                         f"{v['restated']} | " + " | ".join(str(v["cites"].get(k, 0)) for k in keys) + " |")
        lines.append("")
    if r.get("materials"):
        lines.append("Passages (page views): " + ", ".join(
            f"{k} {m['passages']}" + (f" ({m['passageIdsError']})" if m.get("passageIdsError") else "")
            for k, m in r["materials"].items()))
        lines.append("Records (record lists): "
                     + ", ".join(f"{k} {m.get('records', 0)}" for k, m in r["materials"].items())
                     + (f" ({r['recordIdsError']})" if r.get("recordIdsError") else ""))
        lines.append("")
    failures = [f for k in ("found", "cited", "restated") for f in c[k]["failures"]]
    failures += [{"check": "found (not checked)", **u} for u in c["found"].get("unchecked") or []]
    if failures:
        lines += ["## Failures", ""]
        for f in failures:
            what = (leak._named(f["foreign"]) if f.get("foreign") else ", ".join(f["markers"]) if f.get("markers")
                    else f.get("code", ""))
            lines.append(f"- {f['check']} · {f['campaign']} · {f['question']} · {what}")
        lines.append("")
    d = res["deletion"]
    lines += ["## Deletion", ""]
    if not d["systems"]:
        lines.append("- Nothing was made, so nothing was deleted.")
    elif d["kept"]:
        lines.append("- Kept (`--keep`): delete them by hand in the library once diagnosed.")
        lines += [f"- system `{s['id']}` \"{s.get('name')}\" with its campaigns, materials and conversations"
                  for s in d["systems"]]
    else:
        lines.append(f"- {'Finished' if d['finished'] else 'NOT finished'}: "
                     + "; ".join(f"system `{s['id']}` \"{s.get('name')}\": delete {s.get('delete')}, "
                                 f"{'gone' if s.get('gone') else 'still found'}, "
                                 f"{'deleted' if s.get('deleted') else 'deletion not logged'}"
                                 + (f" ({s['error']})" if s.get("error") else "") for s in d["systems"]))
    if d["systems"] and not d["kept"] and not d["finished"]:
        lines.append("- The library may remain in the account: delete these systems by hand (Sistemas, the system, "
                     "delete), which takes their campaigns, materials and conversations: "
                     + ", ".join(f"\"{s.get('name')}\"" for s in d["systems"]))
    if res.get("previousCurrentError"):
        lines.append(f"- The current campaign could not be read before the run ({res['previousCurrentError']}), so it "
                     "was not put back: choose it again in the app")
    if res.get("currentRestored") not in (None, True):
        lines.append(f"- The current campaign was not put back: {res['currentRestored']}")
    lines.append("")
    lines += ["## Questions", "", "| Campaign | Id | Kind | Ended | Found | Cites | Markers | Total | Failed |",
              "|---|---|---|---|---|---|---|---|---|"]
    for t in r.get("turnsDetail") or []:
        lines.append(f"| {t['campaign']} | {t['question']} | {t['kind']} | {t['error'] or t['ended']} | "
                     f"{'-' if t['found'] is None else t['found']} | {', '.join(t['cites']) or '-'} | "
                     f"{', '.join(t['markers']) or '-'} | {sm2._secs(t['ms'])} | {', '.join(t['failed']) or ''} |")
    timings = res.get("timings") or {}
    if timings:
        lines += ["", "Timings (s): " + ", ".join(f"{k} {v}" for k, v in timings.items())]
    return "\n".join(lines) + "\n"


def _ok(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _failures(check: dict) -> str:
    return f"{len(check['failures'])} failure(s)" + (f" ({check['code']})" if check.get("code") else "")


def _codes(errors: dict) -> str:
    return ", ".join(f"{k} {v}" for k, v in errors.items())


def write_result(root: Path, res: dict) -> Path:
    d = root / res["folder"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "result.json").write_text(json.dumps(res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (d / "summary.md").write_text(summary_md(res), encoding="utf-8")
    return d


# ------------------------------------------------------------------ the command

def say(msg: str) -> None:
    print(msg, flush=True)


def runner_config(session_file: Path, token: str, suffix: str, inputs: Path, markers: dict, lim: Limits,
                  keep: bool) -> dict:
    return {"base": "", "credential": "", "session": {"token": token, "file": str(session_file)},
            "suffix": suffix, "systems": leak.SYSTEMS, "campaigns": leak.CAMPAIGNS,
            "materials": [{"key": m["key"], "file": str(inputs / m["filename"]), "filename": m["filename"],
                           "kind": m["kind"], "language": "pt-BR",
                           **({"campaign": m["campaign"]} if "campaign" in m else {"system": m["system"]})}
                          for m in leak.MATERIALS],
            "questions": str(QUESTIONS), "markers": markers["terms"], "pageIds": True, "delete": not keep,
            "budget": lim.budget,
            "limits": {"question": lim.question, "material": lim.material, "indexing": lim.indexing,
                       "poll": lim.poll, "deletion": lim.deletion}}


def _wait_deleted(log_of, ids: list[str], lim: Limits) -> set[str]:
    """Polls the backend log (from the deletion's start) until it records library.system_deleted for every id, or
    `deleted_wait` passes. A stop (Ctrl-C, SIGTERM) ends the wait with what was seen."""
    end = time.monotonic() + lim.deleted_wait
    done: set[str] = set()
    try:
        while True:
            done |= deleted_systems(log_of() or "") & set(ids)
            if done >= set(ids) or time.monotonic() >= end:
                return done
            time.sleep(lim.log_every)
    except KeyboardInterrupt:
        return done


class _Terminated:
    """For the run's duration, the first SIGTERM (a `kill <pid>` of a detached run) raises KeyboardInterrupt, so
    the runner's cleanup (current campaign, deletion) still runs; later ones are ignored while it cleans up."""

    def __init__(self):
        self.seen, self.old = False, None

    def handler(self, signum, frame):
        if not self.seen:
            self.seen = True
            raise KeyboardInterrupt

    def __enter__(self):
        try:
            self.old = signal.signal(signal.SIGTERM, self.handler)
        except ValueError:                        # not the main thread: no handler
            self.old = None
        return self

    def __exit__(self, *exc):
        if self.old is not None:
            signal.signal(signal.SIGTERM, self.old)


def run(session_file: Path, *, settings: Settings | None = None, target: Target | None = None,
        backend_container: str = "gmshield-backend", network: str = "gmshield-app", keep: bool = False,
        lim: Limits | None = None, markers_file: Path = MARKERS) -> int:
    lim = lim or Limits()
    started = datetime.now(timezone.utc)
    try:
        markers = load_markers(markers_file)
    except (OSError, ValueError, KeyError) as e:
        say(f"sm1: cannot start: {markers_file}: {type(e).__name__}")
        return EXIT_STOPPED
    try:
        session = Session(session_file)
    except (Refused, OSError) as e:
        say(f"sm1: cannot start: no session token in {session_file} ({type(e).__name__}); "
            + SIGN_IN_HELP.format(file=session_file))
        return EXIT_STOPPED
    try:
        target = target or sm2.resolve_target(backend_container, network)
    except Refused as e:
        say(f"sm1: cannot start: {e}")
        return EXIT_STOPPED
    if session_file.stat().st_mode & 0o077:
        say(f"sm1: warning: {session_file} is readable by others; it is rewritten with mode 600")
    from .pipeline import single_instance       # pipeline imports the stages, which import sm2

    settings = settings or load_settings()
    with single_instance(settings) as free:
        if not free:
            say("sm1: a pipeline run is in progress; try again when it ends")
            return EXIT_FAIL
        runner = load_runner()
        api = runner.Api(target.base, target.credential, token=session.token, session_file=str(session_file),
                         session_given=True)
        try:
            api.renew_if_due()                    # renew_at 0: a renewal now, before anything is made
        except runner.Stop as e:
            say(f"sm1: cannot start: {e}; " + SIGN_IN_HELP.format(file=session_file))
            return EXIT_STOPPED
        with _Terminated():
            return _measure(api, session_file, settings, target, started, markers, markers_file, lim, keep)


def _measure(api, session_file: Path, settings: Settings, target: Target, started: datetime, markers: dict,
             markers_file: Path, lim: Limits, keep: bool) -> int:
    runner = load_runner()
    artifacts = settings.artifacts
    rel = sm2.releases(artifacts, target.backend_container)
    worker = app_container(target.backend_container, "worker")
    suffix = f"sm1 {started:%Y-%m-%d %H%M%S}"
    since = (started - LOG_LOOKBACK).strftime("%Y-%m-%dT%H:%M:%SZ")
    say(f"sm1: {len(leak.questions())} questions in 2 campaigns, names suffixed \"{suffix}\", release "
        + ", ".join(f"{s} {rel[s]['tag']}" for s in sm2.SERVICES) + ("; keeping the library" if keep else ""))
    record = runner.new_record()
    with tempfile.TemporaryDirectory(prefix="gmshield-sm1-") as tmp:
        inputs = Path(tmp)
        for m in leak.MATERIALS:
            (inputs / m["filename"]).write_bytes(leak.library_pdf(m["source"]))
        cfg = runner_config(session_file, api.token, suffix, inputs, markers, lim, keep)
        runner.run_all(cfg, record, api)
    if record.get("error"):
        say(f"sm1: the runner stopped at {record['error']}")
    ids = [s["id"] for s in (record.get("deletion") or {}).get("systems") or [] if s.get("delete") in
           ("started", "not_found")]
    deleting = datetime.fromtimestamp((record.get("deletion") or {}).get("startedAt") or time.time(), timezone.utc)
    since_deletion = (deleting - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    finished = (_wait_deleted(lambda: container_log(target.backend_container, since_deletion), ids, lim)
                if ids else set())
    backend_log = container_log(target.backend_container, since)
    worker_log = container_log(worker, since)
    result = judge(record, jobs_of_turns(backend_log) if backend_log is not None else None,
                   leak.found_ids(worker_log) if worker_log is not None else None, markers, lim)
    logs = {"backend": log_state(backend_log, started), "worker": log_state(worker_log, started)}
    truncated = [app for app, state in logs.items() if state["possiblyTruncated"]]
    if truncated and result["reason"].startswith("cannot check"):
        result["reason"] += f" ({' and '.join(truncated)} log possibly truncated)"
    names = {s["key"]: runner.named(s["name"], suffix) for s in leak.SYSTEMS}
    deletion = deletion_summary(record, finished | (deleted_systems(backend_log or "") & set(ids)))
    for s in deletion["systems"]:
        s["name"] = names.get(s["key"])
    exit_code = {"pass": EXIT_PASS, "fail": EXIT_FAIL}.get(result["status"], EXIT_STOPPED)
    res = {"kind": "sm1", "startedAt": started.isoformat(timespec="seconds"),
           "endedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "folder": f"{started:%Y-%m-%d-%H%M%S}-{sm2.SAFE_NAME.sub('_', str(rel['backend']['tag']))[:40]}",
           "status": result["status"], "reason": result["reason"], "exitCode": exit_code,
           "target": {"backendContainer": target.backend_container, "network": target.network,
                      "workerContainer": worker},
           "release": rel, "suffix": suffix, "questionsFile": str(QUESTIONS),
           "questionsSha256": hashlib.sha256(QUESTIONS.read_bytes()).hexdigest(),
           "markersSha256": hashlib.sha256(markers_file.read_bytes()).hexdigest(),
           "limits": {"questionS": lim.question, "maxErrors": lim.max_errors, "houseCiteHA": lim.house_cite_ha,
                      "notesCiteNB": lim.notes_cite_nb},
           "logs": logs,
           "runnerError": record.get("error"), "runnerPhase": record.get("phase"),
           "systems": record.get("systems"), "campaignIds": record.get("campaigns"),
           "previousCurrent": record.get("previousCurrent"), "previousCurrentError": record.get("previousCurrentError"),
           "currentRestored": record.get("currentRestored"),
           "deletion": deletion, "sessionRenewals": record.get("renewals"), "timings": record.get("timings"),
           "result": result}
    d = write_result(artifacts / "quality" / "sm1", res)
    say(f"sm1: {result['status'].upper()}: {result['reason']}")
    livro = result["checks"]["houseRuleInLivro"]["failures"]
    say("sm1: Livro: " + ("no answer mentioned the house rule" if not livro else
                          "; ".join(f"{f['question']} {', '.join(f['markers'])}" for f in livro)))
    say("sm1: library " + ("kept (--keep)" if deletion["kept"] else
                           "deleted" if deletion["finished"] else "deletion NOT finished (see the summary)"
                           if deletion["systems"] else "never made"))
    say(f"sm1: result in {d}")
    return exit_code
