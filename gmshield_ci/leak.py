"""The SM-1 leak gate with the fake model (Story 3.13, part A): two campaigns of one system never leak.

On its own stack, started as the end-to-end test starts it (`e2e.with_stack`: the three apps in test mode on a
throwaway internal network, labelled with the run, beside Postgres, Redis, a stand-in Qdrant and a stand-in Ollama,
the fake model answering), quality/sm1/runner.py runs with the worker image's Python (`python -I`, read-only mount,
on that network) and drives the backend's public API as one new account (`stand-in.sm1.leak@example.test`):

- the library: system "Vale de Ferro" with its rulebook `R`; its campaigns "Casa", with house rules `HA` that each
  contradict a rule of `R`, and "Livro", with by-the-book session notes `NB`; a second system "Mar de Cinzas" with
  its rulebook `X`. Four text-only PDFs of invented Portuguese content (quality/sm1/library/, made with
  sm2.text_pdf), uploaded, accepted and indexed. Scopes stay at their defaults, so Casa may use R + HA and Livro
  R + NB;
- the 40 questions of quality/sm1/questions.json (20 pt-BR, 20 en; kinds house, notes, neutral), each asked in both
  campaigns, one at a time;
- the control: Livro's other tier on, one house question, the tier off again.

Then, from Postgres (each material's passages by the version id its upload returned; each turn's job and the
campaign of its conversation) and the worker's log (`retrieval.search_done`: the ids each job found and fetched), the
five checks:
1. found and fetched: every id a campaign's job found is inside the campaign's allowed set;
2. cited: every citation event's id and every done reference's ids are inside it;
3. clean ends: every turn ends in done, not stopped; an error fails the gate, scope.passage_refused as a found leak;
4. not empty: in each campaign every allowed material is cited, and every house question asked in Casa cites HA;
5. control: the control question's found ids hold HA ids, else the gate cannot see a leak.

Any failed check fails the run (no gate key, as e2e). The stage runs in full develop runs of the backend, frontend
and worker, after e2e, with `[limits] leak` (1800 s) for the whole test. `python3 -m gmshield_ci leak` runs it
against the latest develop images, with its files in artifacts/quality/leak/<UTC yyyy-mm-dd-HHMMSS>/.

Kept: result.json and summary.md (ids, counts, verdicts, error codes and timings), the runner's record
(runner.json, ids only) and log, the stage's log and the logs of every container. No answer or passage text is
written to any of them.
"""
from __future__ import annotations

import json
import shutil
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from . import e2e
from .config import RUNNER_DIR, Settings
from .dockerops import Docker, capture, container_logs
from .sm2 import text_pdf

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import Run

TITLE = "Leak test SM-1 (fake model)"
QUALITY = RUNNER_DIR / "quality" / "sm1"
LIBRARY = QUALITY / "library"
QUESTIONS = QUALITY / "questions.json"
DEFAULT_LIMIT = 1800
PAGE_BREAK = "---"
BACKEND = "http://stand-in-backend:8080"  # NOSONAR(S5332) the test-mode backend on the run's internal network, which has no TLS
# The frontend's fixed service credential of test mode (GMshield-backend application-test-mode.yaml): public on
# purpose, and refused by the backend outside test mode.
TEST_MODE_FRONTEND = "gmshield-test-mode-frontend-credential-not-a-secret"
CODE = "stand-in.sm1.leak@example.test"          # the Google stand-in's identity of the runner's own account
USERNAME = "sm1_leak"
SYSTEMS = [{"key": "vale", "name": "Vale de Ferro"}, {"key": "mar", "name": "Mar de Cinzas"}]
CAMPAIGNS = [{"key": "casa", "name": "Casa", "system": "vale"}, {"key": "livro", "name": "Livro", "system": "vale"}]
NAMES = {c["key"]: c["name"] for c in CAMPAIGNS}
MATERIALS = [
    {"key": "R", "source": "R.txt", "filename": "vale-de-ferro-regras.pdf", "kind": "rulebook", "system": "vale"},
    {"key": "HA", "source": "HA.txt", "filename": "casa-regras-da-casa.pdf", "kind": "homebrew", "campaign": "casa"},
    {"key": "NB", "source": "NB.txt", "filename": "livro-notas-de-sessao.pdf", "kind": "campaign_notes",
     "campaign": "livro"},
    {"key": "X", "source": "X.txt", "filename": "mar-de-cinzas-regras.pdf", "kind": "rulebook", "system": "mar"},
]
# Each campaign's allowed materials with its scope at the defaults (campaign and system tiers on, other tier off).
ALLOWED = {"casa": ("R", "HA"), "livro": ("R", "NB")}
HOUSE_RULES = "HA"                                # what every house question asked in Casa must cite
CONTROL = {"campaign": "livro", "question": "q01"}
CHECKS = ("found", "cited", "ended", "exercised", "control")
MAX_NAMED = 3                                     # foreign ids named in the stage's one-line reason
PASSAGES_SQL = "select id, version_id from passage"
TURNS_SQL = ("select t.id, t.job_id, c.campaign_id from turn t "
             "join conversation c on c.owner_id = t.owner_id and c.id = t.conversation_id")


class LeakError(e2e.E2EError):
    """The stage cannot go on (Postgres unreadable, the runner gone): an error, with the files kept so far."""


# ------------------------------------------------------------------ the library and the runner

def pages(source: str) -> list[list[str]]:
    """A library file's pages: its lines, a line holding only PAGE_BREAK starting a new page."""
    out: list[list[str]] = [[]]
    for line in (LIBRARY / source).read_text(encoding="utf-8").splitlines():
        if line.strip() == PAGE_BREAK:
            out.append([])
        else:
            out[-1].append(line)
    return [p for p in out if any(x.strip() for x in p)]


def library_pdf(source: str) -> bytes:
    return text_pdf(pages(source), encoding="WinAnsiEncoding")


def questions() -> list[dict]:
    return json.loads(QUESTIONS.read_text(encoding="utf-8"))


def runner_config(budget: int) -> dict:
    return {"base": BACKEND, "credential": TEST_MODE_FRONTEND, "code": CODE, "username": USERNAME,
            "systems": SYSTEMS, "campaigns": CAMPAIGNS,
            "materials": [{"key": m["key"], "file": f"/in/{m['filename']}", "filename": m["filename"],
                           "kind": m["kind"], "language": "pt-BR",
                           **({"campaign": m["campaign"]} if "campaign" in m else {"system": m["system"]})}
                          for m in MATERIALS],
            "questions": "/sm1/questions.json", "control": CONTROL, "out": "/out/runner.json", "budget": budget,
            "limits": {"question": 120, "material": 600, "indexing": 600, "poll": 1.0}}


def runner_args(sess: e2e.Session, worker: e2e.App, inputs: Path) -> dict:
    """The runner as the stand-in Ollama runs: the worker image's Python, isolated, from a read-only mount, with a
    read-only root and no capability; it writes only its record, to the stage's folder."""
    return {"name": f"{sess.prefix}-runner", "image": worker.image, "entrypoint": "python",
            "args": ["-I", "/sm1/runner.py", "/in/config.json"],
            "env": {"PYTHONDONTWRITEBYTECODE": "1"},
            "mounts": [(inputs, "/in", "ro"), (QUALITY, "/sm1", "ro"), (sess.dir, "/out", "rw")],
            "extra": ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]}


# ------------------------------------------------------------------ what the apps recorded

def psql(container: str, sql: str) -> list[list[str]]:
    """Rows of a fixed query, run in the run's Postgres container with the test-mode user."""
    rc, out = capture(["docker", "exec", container, "psql", "-U", "gmshield", "-d", "gmshield", "-AtX",
                       "-v", "ON_ERROR_STOP=1", "-F", ",", "-c", sql], timeout=60)
    if rc != 0:
        raise LeakError(f"cannot read Postgres (exit {rc})")
    return [line.split(",") for line in out.splitlines() if line.strip()]


def read_passages(container: str) -> dict[str, str]:
    """{passage id: version id}."""
    return {r[0]: r[1] for r in psql(container, PASSAGES_SQL) if len(r) == 2}


def read_turns(container: str) -> dict[str, dict]:
    """{turn id: {job, campaign}}: each turn's job and its conversation's campaign."""
    return {r[0]: {"job": r[1], "campaign": r[2]} for r in psql(container, TURNS_SQL) if len(r) == 3}


def found_ids(log_text: str) -> dict[str, set[str]]:
    """{job id: the passage ids it found and fetched}, from the worker log's retrieval.search_done lines (one per
    attempt; a line with no tier searched has no ids). Each line may carry `docker logs --timestamps`' prefix."""
    out: dict[str, set[str]] = {}
    for line in log_text.splitlines():
        start = line.find("{")
        if start < 0 or "retrieval.search_done" not in line:
            continue
        try:
            d = json.loads(line[start:])
        except ValueError:
            continue
        if not isinstance(d, dict) or d.get("event") != "retrieval.search_done" or not d.get("jobId"):
            continue
        out.setdefault(str(d["jobId"]), set()).update(str(i) for i in d.get("ids") or [])
    return out


# ------------------------------------------------------------------ the checks (pure)

def _named(foreign: list[dict]) -> str:
    named = ", ".join(f"{f['material']}:{f['id']}" for f in foreign[:MAX_NAMED])
    return named + (f" (+{len(foreign) - MAX_NAMED} more)" if len(foreign) > MAX_NAMED else "")


def judge(record: dict | None, passages: dict[str, str], turns_db: dict[str, dict], found: dict[str, set[str]],
          rc: int = 0, allowed: dict[str, tuple[str, ...]] | None = None, asked: list[dict] | None = None) -> dict:
    """The five checks over the runner's record, Postgres' passages and turns, and the worker's found ids. Returns
    the result: verdict (passed | failed | error), reason, failures, per-campaign and per-turn counts, the control.
    Only ids, counts, codes and timings: the record holds no text, and none is added."""
    allowed = allowed or ALLOWED
    asked = asked if asked is not None else questions()
    if rc == 124:
        return {"verdict": "error", "reason": "timed out", "failures": []}
    if not isinstance(record, dict) or not isinstance(record.get("turns"), list):
        return {"verdict": "error", "reason": f"the runner wrote no record (exit {rc})", "failures": []}
    materials = {k: m for k, m in (record.get("materials") or {}).items() if isinstance(m, dict)}
    by_version = {str(m.get("versionId")): key for key, m in materials.items()}

    def material(pid: str) -> str:
        return by_version.get(passages.get(pid, ""), "unknown")

    def foreign(ids) -> list[dict]:
        return [{"id": p, "material": material(p)} for p in sorted(ids)]

    campaign_key = {str(v): k for k, v in (record.get("campaigns") or {}).items()}
    allowed_ids = {c: {p for p in passages if material(p) in keys} for c, keys in allowed.items()}
    turns = [t for t in record["turns"] if isinstance(t, dict)]
    by_turn = {str(t.get("turnId")): t for t in turns if t.get("turnId")}
    control_turn = next((t for t in turns if t.get("phase") == "control"), None)
    failures: list[dict] = []

    # 1. found and fetched: every job of a turn of a campaign, from the worker's own record (the control's aside)
    turn_of_job = {d.get("job"): tid for tid, d in turns_db.items()}
    in_order = [turns_db[str(t.get("turnId"))].get("job") for t in turns if str(t.get("turnId")) in turns_db]
    for job in [j for j in in_order if j in found] + sorted(set(found) - set(in_order)):
        tid = turn_of_job.get(job)
        if tid is None:
            failures.append({"check": "found", "campaign": None, "question": None, "job": job,
                             "code": "job of no turn", "foreign": foreign(found[job])})
            continue
        t = by_turn.get(tid) or {}
        if t is control_turn:
            continue
        camp = campaign_key.get(turns_db[tid].get("campaign"))
        out = found[job] - allowed_ids.get(camp, set())
        if out:
            failures.append({"check": "found", "campaign": NAMES.get(camp, camp),
                             "question": t.get("question") or f"turn {tid}",
                             "job": job, "foreign": foreign(out)})

    cited_by = {c: Counter() for c in allowed}
    rows = []
    for t in turns:
        if t is control_turn:
            continue
        if record.get("error") and not t.get("turnId") and t.get("ended") == "ask" and not t.get("error"):
            continue            # never made: the runner stopped before posting it, and its error says why
        camp, qid, name = t.get("campaign"), t.get("question"), NAMES.get(t.get("campaign"), str(t.get("campaign")))
        ok_ids = allowed_ids.get(camp, set())
        db = turns_db.get(str(t.get("turnId"))) or {}
        job = db.get("job")
        got = found.get(job) if job else None
        here = [f for f in failures if f.get("job") is not None and f.get("job") == job]

        def fail(check: str, **extra) -> None:
            item = {"check": check, "campaign": name, "question": qid, **extra}
            here.append(item)
            failures.append(item)

        if t.get("turnId") and not db:
            fail("ended", code="turn.not_in_postgres")
        elif db and campaign_key.get(db.get("campaign")) != camp:
            fail("ended", code="turn.other_campaign")
        # 2. cited: the citation events as relayed, and the done event's references
        cited = {str(p) for p in t.get("citations") or []} | {str(p) for ref in t.get("references") or []
                                                               for p in ref}
        if cited - ok_ids:
            fail("cited", foreign=foreign(cited - ok_ids))
        for key in {material(p) for p in cited & ok_ids}:
            cited_by.setdefault(camp, Counter())[key] += 1
        # 3. clean ends
        error, ended = t.get("error"), t.get("ended")
        if error == "scope.passage_refused":
            fail("found", code=error)
        elif ended != "done" or error:
            fail("ended", code=error or ended or "unknown")
        elif t.get("stopped"):
            fail("ended", code="stopped")
        elif got is None:
            fail("exercised", code="no retrieval record")
        # 4. not empty: a house question in Casa cites the house rules
        if (ended == "done" and camp == "casa" and t.get("kind") == "house"
                and not any(material(p) == HOUSE_RULES for p in cited & ok_ids)):
            fail("exercised", code=f"does not cite {HOUSE_RULES}")
        rows.append({"campaign": name, "question": qid, "kind": t.get("kind"), "turnId": t.get("turnId"),
                     "jobId": job, "scopeVersion": t.get("scopeVersion"), "ended": ended, "error": error,
                     "stopped": bool(t.get("stopped")), "found": len(got) if got is not None else None,
                     "cited": len(cited), "lastEventId": t.get("lastEventId"), "ms": t.get("ms"),
                     "clean": not here, "failed": sorted({f["check"] for f in here})})
    # 4. not empty: every allowed material of a campaign is cited at least once
    for camp, keys in allowed.items():
        for key in keys:
            if not cited_by[camp][key]:
                failures.append({"check": "exercised", "campaign": NAMES.get(camp, camp), "question": None,
                                 "code": f"never cites {key}"})
    # 5. the control
    control = _control(control_turn, record.get("control"), turns_db, found, material)
    if control["status"] not in ("ok", "not_run"):
        failures.append({"check": "control", "campaign": NAMES.get(CONTROL["campaign"]),
                         "question": CONTROL["question"], "code": control["status"]})

    expected = len(asked) * len(allowed)
    campaigns = {}
    for c, keys in allowed.items():
        mine = [r for r in rows if r["campaign"] == NAMES.get(c, c)]
        campaigns[NAMES.get(c, c)] = {
            "id": (record.get("campaigns") or {}).get(c), "allowed": list(keys),
            "scopeVersion": ((record.get("scopes") or {}).get(c) or {}).get("version"),
            "turns": len(mine), "clean": sum(1 for r in mine if r["clean"]), "cited": dict(cited_by[c])}
    result = {"questions": len(asked), "expected": expected, "turns": len(rows),
              "clean": sum(1 for r in rows if r["clean"]), "campaigns": campaigns,
              "materials": {k: {"versionId": m.get("versionId"),
                                "passages": sum(1 for v in passages.values() if v == m.get("versionId"))}
                            for k, m in materials.items()},
              "control": control, "failures": failures, "turnsDetail": rows,
              "runner": {"phase": record.get("phase"), "error": record.get("error"),
                         "timings": record.get("timings") or {}, "renewals": record.get("renewals")}}
    result["verdict"], result["reason"] = _verdict(failures, record, len(rows), expected, control)
    return result


def _control(turn: dict | None, rec: dict | None, turns_db: dict, found: dict, material) -> dict:
    """status: ok, not_run, or why the control failed."""
    out = {"status": "not_run", "turnId": None, "foundHouseRules": 0, "scopeVersionOn": None, "scopeVersionOff": None,
           "otherTierOff": None}
    if isinstance(rec, dict):
        out.update({k: rec.get(k) for k in ("scopeVersionOn", "scopeVersionOff", "otherTierOff")})
    if turn is None:
        return out
    out["turnId"] = turn.get("turnId")
    job = (turns_db.get(str(turn.get("turnId"))) or {}).get("job")
    ids = found.get(job, set()) if job else set()
    out["foundHouseRules"] = sum(1 for p in ids if material(p) == HOUSE_RULES)
    if turn.get("ended") != "done" or turn.get("error"):
        out["status"] = f"control question ended in {turn.get('error') or turn.get('ended')}"
    elif not out["foundHouseRules"]:
        out["status"] = "control failed: the check cannot see a leak"
    elif out["otherTierOff"] is not True:
        out["status"] = "the other tier was not turned off again"
    else:
        out["status"] = "ok"
    return out


def _verdict(failures: list[dict], record: dict, turns: int, expected: int, control: dict) -> tuple[str, str]:
    def first(check: str) -> dict | None:
        return next((f for f in failures if f["check"] == check), None)

    for check, word in (("found", "leak found"), ("cited", "leak cited")):
        f = first(check)
        if f:
            if f.get("campaign") is None:
                return "failed", f"{word}: job {f.get('job')} of no turn {_named(f['foreign'])}".rstrip()
            what = _named(f["foreign"]) if f.get("foreign") else f.get("code", "")
            return "failed", f"{word}: {f['campaign']} {f['question']} {what}".rstrip()
    f = first("ended")
    if f:
        return "failed", f"{f['question']} {f['campaign']}: {f['code']}"
    if record.get("error"):
        return "error", f"the runner stopped at {record['error']}"
    if turns < expected:
        return "error", f"only {turns}/{expected} questions asked"
    f = first("exercised")
    if f:
        where = f"{f['campaign']} {f['question']}" if f.get("question") else f["campaign"]
        return "failed", f"not exercised: {where} {f['code']}"
    if control["status"] == "not_run":
        return "error", "the control question was not asked"
    if control["status"] != "ok":
        return "error", control["status"]
    return "passed", f"{turns}/{expected} clean, control ok"


def summary(result: dict, shas: dict) -> str:
    """summary.md: the verdict, per-campaign counts, the control and the failures; ids only."""
    lines = ["# SM-1 leak test (fake model)", "",
             f"Verdict: **{result.get('verdict', 'error').upper()}**: {result.get('reason', '')}", ""]
    if shas:
        lines += ["Images: " + ", ".join(f"{k} `{v[:8]}`" for k, v in shas.items()), ""]
    if result.get("campaigns"):
        keys = [m["key"] for m in MATERIALS]
        lines += ["| Campaign | Allowed | Turns | Clean | " + " | ".join(f"Cites {k}" for k in keys) + " |",
                  "|---|---|---|---|" + "---|" * len(keys)]
        for name, c in result["campaigns"].items():
            lines.append(f"| {name} | {' + '.join(c['allowed'])} | {c['turns']} | {c['clean']} | "
                         + " | ".join(str(c["cited"].get(k, 0)) for k in keys) + " |")
        lines.append("")
    if result.get("materials"):
        lines.append("Passages: " + ", ".join(f"{k} {m['passages']}" for k, m in result["materials"].items()))
        lines.append("")
    ctl = result.get("control")
    if ctl:
        lines += [f"Control (Livro, other tier on, {CONTROL['question']}): {ctl['status']}; "
                  f"{ctl['foundHouseRules']} {HOUSE_RULES} id(s) found; scope versions {ctl['scopeVersionOn']} "
                  f"(on), {ctl['scopeVersionOff']} (off)", ""]
    if result.get("failures"):
        lines += ["## Failures", ""]
        for f in result["failures"]:
            where = " · ".join(str(x) for x in (f.get("campaign"), f.get("question"), f.get("job")) if x)
            what = _named(f["foreign"]) if f.get("foreign") else f.get("code", "")
            lines.append(f"- {f['check']} · {where} · {what}")
        lines.append("")
    timings = (result.get("runner") or {}).get("timings") or {}
    if timings:
        lines += ["Timings (s): " + ", ".join(f"{k} {v}" for k, v in timings.items()), ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ the test

def execute(sess: e2e.Session, own: e2e.App | None):
    """Runs the test; returns (outcome, metrics, files, detail) as a stage does. Everything it starts is removed."""
    outcome, reason, result, apps = e2e.with_stack(
        sess, own, lambda by, net, log, containers: _session(sess, by, net, containers))
    shas = {a.service: a.sha for a in apps}
    final = {**(result or {"verdict": "error", "failures": []}), "outcome": outcome, "reason": reason,
             "shas": shas, "images": {a.service: a.image for a in apps}}
    if outcome != "ok" and (not result or final.get("verdict") == "passed"):
        final["verdict"] = "error"
    (sess.dir / "result.json").write_text(json.dumps(final, indent=2))
    (sess.dir / "summary.md").write_text(summary(final, shas))
    sess.keep("result.json")
    sess.keep("summary.md")
    metrics = {"shas": shas, "verdict": final.get("verdict"), "turns": final.get("turns", 0),
               "clean": final.get("clean", 0), "failures": len(final.get("failures") or []),
               "control": (final.get("control") or {}).get("status")}
    short = ", ".join(f"{k} {v[:8]}" for k, v in shas.items())
    if outcome == "ok":
        return "ok", metrics, list(sess.files), f"{reason} ({short})"
    metrics["error"] = reason
    return "error", metrics, list(sess.files), f"{reason}{f' ({short})' if short else ''}"


def _session(sess: e2e.Session, by: dict[str, e2e.App], net: str, containers: dict):
    inputs = sess.work / "in"
    inputs.mkdir(parents=True, exist_ok=True)
    for m in MATERIALS:
        (inputs / m["filename"]).write_bytes(library_pdf(m["source"]))
    budget = max(sess.left() - 60, 1)
    (inputs / "config.json").write_text(json.dumps(runner_config(budget)))
    inputs.chmod(0o755)
    for f in inputs.iterdir():
        f.chmod(0o644)
    spec = runner_args(sess, by["worker"], inputs)
    sess.log(f"leak: runner started (budget {budget}s)")
    (sess.dir / "runner.json").unlink(missing_ok=True)
    rc = sess.docker.run(spec["name"], spec["image"], spec["args"], log=sess.dir / "runner.log",
                         timeout=sess.left(), network=net, env=spec["env"], entrypoint=spec["entrypoint"],
                         mounts=spec["mounts"], extra=spec["extra"])
    sess.keep("runner.log")
    sess.keep("runner.json")
    record = _read(sess.dir / "runner.json")
    passages = read_passages(containers["postgres"])
    turns_db = read_turns(containers["postgres"])
    worker_log = sess.dir / "worker.log"
    container_logs(containers["worker"], worker_log)
    found = found_ids(worker_log.read_text(encoding="utf-8", errors="replace"))
    result = judge(record, passages, turns_db, found, rc)
    return ("ok" if result["verdict"] == "passed" else "error"), result["reason"], result


def _read(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


# ------------------------------------------------------------------ entry points

def stage(run: "Run"):
    """develop (full) of the backend, frontend or worker, after e2e: the run's image with the others' latest."""
    c = run.contract
    if c.service not in e2e.SERVICES:
        return "skipped", {}, [], "not an app of the leak test"
    if not run.image_built:
        return "skipped", {}, [], "no image to test"
    sess = e2e.Session(s=run.s, id=run.id, docker=run.docker, dir=run.dir / "leak", work=run.work / "leak",
                       rel="leak/", log=run.log, prefix="leak")
    sess.deadline = time.monotonic() + run.s.limit("leak", DEFAULT_LIMIT)
    own = e2e.App(c.service, run.repo.name, run.sha, run.local_image, c, run.src)
    return execute(sess, own)


def standalone(s: Settings) -> int:
    """`python3 -m gmshield_ci leak`: the test against the latest develop image of all three apps, holding the poll
    lock (a poll's crash cleanup would remove its containers). Exit 0 only when every check passed."""
    from .pipeline import single_instance     # pipeline imports this module

    when = datetime.now(timezone.utc)
    run_id = f"leak-{when:%Y%m%d-%H%M%S}"
    out = s.artifacts / "quality" / "leak" / e2e.folder_name(when)
    docker = Docker(s.ci_slice, run_id, s.instance)
    sess = e2e.Session(s=s, id=run_id, docker=docker, dir=out, work=s.work / run_id,
                       log=lambda msg: print(msg, flush=True), prefix="leak")
    with single_instance(s) as ok:
        if not ok:
            print("a pipeline run is in progress; try again when it ends")
            return 1
        t0 = time.monotonic()
        try:
            sess.deadline = time.monotonic() + s.limit("leak", DEFAULT_LIMIT)
            outcome, metrics, _, detail = execute(sess, None)
        finally:
            docker.cleanup()
            shutil.rmtree(sess.work, ignore_errors=True)
    print(f"leak: {'PASSED' if outcome == 'ok' else 'FAILED'}: {detail} in {round(time.monotonic() - t0)}s; "
          f"files in {out}")
    return 0 if outcome == "ok" else 1
