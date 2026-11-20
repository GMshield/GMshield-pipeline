"""The end-to-end test with the fake model (Story 2.9): the three apps together, driven through a real browser.

On one throwaway internal network (no internet), labelled with the run:
- Postgres and Redis as the staging services (`postgres`, `redis`), a stand-in Qdrant (`stand-in-qdrant`, the pinned
  Qdrant with no key and its storage on tmpfs) and a stand-in Ollama (`stand-in-ollama`, quality/e2e/stand_in_ollama.py
  run with the worker image's Python);
- the backend (`stand-in-backend`), the worker (no alias) and the frontend (`frontend`), each started as DAST starts the
  app under test: `config.container_args(..., "staging")` with its own contract, read at its image's commit, so with
  GMSHIELD_MODE=test, its caps, hardening, tmpfs, throwaway volumes and certificates. A contract variable that points
  at a production address the test mode would otherwise use (`STAND_IN_ENV`) is set to its stand-in instead;
- quality/e2e/driver.py in Playwright's image (with the `playwright` package added, quality/e2e/Dockerfile), inside the frontend container's network namespace
  (`--network container:<frontend>`), so the browser opens http://localhost:3000 and the `__Host-` Secure cookies work.

The driver signs in through the Google stand-in, uploads a generated 2-page PDF, accepts it and waits for indexing, asks
about one invented fact in it (the worker's fake model answers, citing what retrieval handed it), and opens a reference.
Any failed step, an app that never becomes healthy, a missing image, a Content-Security-Policy violation reported at
any time, or the time limit is an error, and so fails the run: the stage has no gate key. The driver image is built
first, when missing, within its own 900 s; then `[limits] e2e` (1200 s) starts: it is checked between the start-up
phases (each start-up wait also keeps its own `[limits] startup`) and bounds the browser's run.

Images: the run's own, and for each other app `gmshield-ci/<service>:<sha>` of that repo's latest develop run in
state.json, whatever its result (after a contract change spanning two repos, one manual run of the first repo tests it
against the second's new image). `python3 -m gmshield_ci e2e` runs the same test against the latest develop image of
all three, with its files in artifacts/quality/e2e/<UTC yyyy-mm-dd-HHMMSS>/.

Kept: result.json (each step's status, seconds and error, the three shas), the failed step's screenshot, the driver's
log, the stage's log and the logs of every container. No answer or passage text is written to them; a failure screenshot
shows only the test's invented PDF and the fake model's answer, never library text.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from . import gitops, stages
from .config import RUNNER_DIR, Contract, ContractError, Settings, container_args, load_contract
from .dockerops import Docker, capture, container_logs, inspect, sh
from .sm2 import text_pdf

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import Run

TITLE = "End-to-end (fake model)"
SERVICES = ("backend", "frontend", "worker")
# Each app's name on the network: the hostnames the other apps' test modes expect.
ALIASES: dict[str, str | None] = {"backend": "stand-in-backend", "frontend": "frontend", "worker": None}
STEPS = ("sign_in", "upload", "accept", "ask", "open_reference")
QUALITY = RUNNER_DIR / "quality" / "e2e"
MESSAGES = Path("src") / "messages" / "en.json"            # the frontend's labels, read by the driver
FRONTEND_PORT = 3000
OLLAMA_PORT = 11434
QDRANT_PORT = 6333
# Contract variables that name a production address; the test mode reads them when set, so they point at the stand-in.
STAND_IN_ENV = {"GMSHIELD_OLLAMA_URL": f"http://stand-in-ollama:{OLLAMA_PORT}"}  # NOSONAR: test-mode stand-in on the run's internal network, which has no TLS
DEFAULT_LIMIT = 1200
USERNAME = "e2e_gm"
PDF_NAME = "e2e-wardens-of-the-fen.pdf"
# The invented fact the question asks about (page 2 of the generated PDF).
FACT = "The Lantern of Vessa burns for exactly nineteen hours on one drop of starfire oil."
QUESTION = "How long does the Lantern of Vessa burn on one drop of starfire oil?"
PAGES = [
    ["Wardens of the Fen", "",
     "Chapter 1: The Saltmarsh Wardens", "",
     "The Saltmarsh Wardens keep the causeways of the Grey Fen open between",
     "the river towns. A Warden carries a reed horn, a hooked staff and a",
     "ledger of debts owed by travellers who were pulled out of the mire.",
     "",
     "Rule: a creature that ends its turn in deep mire sinks one step. At",
     "three steps it is held fast until someone pulls it out with a rope,",
     "a staff or a successful Strength check against difficulty 13.",
     "",
     "Wardens never sleep on the causeway itself. They camp on the stilt",
     "platforms called perches, each marked with a painted heron."],
    ["Chapter 2: Relics of the Fen", "",
     FACT,
     "Its light shows the safe stones of a causeway, even under water.",
     "",
     "The Bell of Low Tides rings by itself when the fen rises. A Warden who",
     "hears it must leave the causeway before the next sunrise.",
     "",
     "The Heron Seal opens every perch gate of the Grey Fen. Only the eldest",
     "Warden of each town may carry it, and it is passed on at midwinter."],
]


class E2EError(Exception):
    """The stage cannot go on: an error, with the files kept so far."""


class TimedOut(E2EError):
    pass


@dataclass
class App:
    service: str
    repo: str
    sha: str
    image: str
    contract: Contract
    src: Path


@dataclass
class Session:
    """What the stage helpers of stages.py need from a run: settings, ids, Docker and folders."""
    s: Settings
    id: str
    docker: Docker
    dir: Path                          # results (run.dir/e2e, or artifacts/quality/e2e/<stamp>)
    work: Path                         # scratch, removed afterwards
    rel: str = ""                      # `dir` relative to the run's folder, for the stage's file list
    log: Callable[[str], None] = print
    deadline: float = 0.0
    files: list[str] = field(default_factory=list)

    def left(self) -> int:
        """Whole seconds left before the stage's limit; TimedOut when none are."""
        left = int(self.deadline - time.monotonic())
        if left <= 0:
            raise TimedOut("timed out")
        return left

    def keep(self, name: str) -> None:
        if (self.dir / name).exists() and f"{self.rel}{name}" not in self.files:
            self.files.append(f"{self.rel}{name}")


def pdf_bytes() -> bytes:
    """The test's 2-page PDF of invented game content."""
    return text_pdf(PAGES)


# ------------------------------------------------------------------ images

def _image_exists(ref: str) -> bool:
    return capture(["docker", "image", "inspect", "--format", "{{.Id}}", ref])[0] == 0


def latest_develop(s: Settings) -> dict:
    """{repo: sha} of each repo's latest develop run, from state.json (whatever its result)."""
    try:
        state = json.loads((s.state_dir / "state.json").read_text())
    except (FileNotFoundError, ValueError):
        return {}
    return {repo: (b.get("develop") or {}).get("sha") for repo, b in state.items() if isinstance(b, dict)}


def repo_of(s: Settings, service: str) -> str:
    want = f"gmshield-{service}"
    return next((r.name for r in s.repos if r.name.lower() == want), f"GMshield-{service}")


def select_apps(sess: Session, own: App | None) -> list[App]:
    """The three apps: `own` (the run's image), and for the others the image of their latest develop run, with the
    contract read from their mirror at that commit. E2EError names a repo without an image."""
    shas = latest_develop(sess.s)
    apps = []
    for svc in SERVICES:
        if own is not None and own.service == svc:
            apps.append(own)
            continue
        repo = repo_of(sess.s, svc)
        sha = shas.get(repo)
        image = f"gmshield-ci/{svc}:{sha}"
        if not sha or not _image_exists(image):
            raise E2EError(f"no develop image of {repo}; run its develop pipeline")
        src = sess.work / "src" / svc
        try:
            gitops.export(sess.s.mirrors / f"{repo}.git", sha, src)
            contract = load_contract(src, repo)
        except (gitops.GitError, ContractError, OSError) as e:
            raise E2EError(f"cannot read the contract of {repo} at {sha[:8]}: {e}") from None
        apps.append(App(svc, repo, sha, image, contract, src))
    return apps


# ------------------------------------------------------------------ containers

def cname(sess: Session, name: str) -> str:
    return f"gmshield-ci-{sess.id}-e2e-{name}"


def app_args(sess: Session, app: App, network: str, certs: Path | None) -> list[str]:
    """`docker run` of one app, as DAST starts the app under test, under its test-mode hostname."""
    c = app.contract
    extra = {k: v for k, v in STAND_IN_ENV.items() if k in c.env or k in c.staging_env}
    return container_args(c, sess.s, "staging", name=cname(sess, app.service), image=app.image, network=network,
                          labels=sess.docker.labels, run_id=sess.id, certs_dir=certs,
                          alias=ALIASES[app.service], extra_env=extra)


def qdrant_args(sess: Session) -> dict:
    return {"name": "e2e-stand-in-qdrant", "image": sess.s.images["qdrant"], "args": [],
            "env": {"QDRANT__TELEMETRY_DISABLED": "true"},
            "extra": ["--network-alias", "stand-in-qdrant", "--tmpfs", "/qdrant/storage", "--tmpfs", "/qdrant/snapshots"]}


def ollama_args(sess: Session, worker: App) -> dict:
    return {"name": "e2e-stand-in-ollama", "image": worker.image,
            "args": ["-I", "/e2e/stand_in_ollama.py", str(OLLAMA_PORT)], "entrypoint": "python",
            "mounts": [(QUALITY, "/e2e", "ro")],
            "extra": ["--network-alias", "stand-in-ollama", "--read-only", "--cap-drop", "ALL",
                      "--security-opt", "no-new-privileges"]}


DRIVER_BUILD = ("Dockerfile", "requirements.txt")


def driver_image(s: Settings) -> str:
    """The driver image's tag: Playwright's pinned image plus the `playwright` package (quality/e2e/Dockerfile),
    named by a hash of what it is built from, so a change to any of them builds a new one."""
    h = hashlib.sha256(s.images["playwright"].encode())
    for f in DRIVER_BUILD:
        h.update((QUALITY / f).read_bytes())
    return f"gmshield-ci/e2e-driver:{h.hexdigest()[:12]}"


DRIVER_BUILD_LIMIT = 900


def ensure_driver_image(sess: Session, log: Path) -> str:
    """Builds the driver image in the CI slice when it is missing (it needs the internet: PyPI, by hash only), within
    its own DRIVER_BUILD_LIMIT, before the test's deadline starts. It is kept between runs; housekeeping may remove
    it, and the next run builds it again."""
    tag = driver_image(sess.s)
    if _image_exists(tag):
        return tag
    rc = sh(["docker", "buildx", "build", "--progress=plain", "--cgroup-parent", sess.s.ci_slice,
             "--build-arg", f"PLAYWRIGHT_IMAGE={sess.s.images['playwright']}", "--label", "gmshield-ci.e2e-driver=1",
             "-t", tag, "--load", str(QUALITY)], log, DRIVER_BUILD_LIMIT)
    if rc != 0:
        raise E2EError(f"the driver image failed to build (exit {rc})")
    return tag


def driver_args(sess: Session, frontend: str, inputs: Path, messages: Path) -> dict:
    return {"name": "e2e-driver", "image": driver_image(sess.s),
            "args": ["python3", "-I", "/e2e/driver.py", "/in/config.json"],
            "network": f"container:{frontend}", "env": {"HOME": stages.CONTAINER_HOME},
            "mounts": [(inputs, "/in", "ro"), (QUALITY, "/e2e", "ro"), (messages, "/messages/en.json", "ro"),
                       (sess.dir, "/out", "rw"), stages.private_home(sess, "e2e-driver")]}


def _start(sess: Session, spec: dict, network: str | None, log: Path) -> str:
    rc = sess.docker.run(spec["name"], spec["image"], spec["args"], log=log, timeout=300, network=network,
                         env=spec.get("env"), user=None, detach=True, entrypoint=spec.get("entrypoint"),
                         mounts=spec.get("mounts", []), extra=spec.get("extra", []))
    if rc != 0:
        raise E2EError(f"{spec['name'].removeprefix('e2e-')} failed to start")
    return f"gmshield-ci-{sess.id}-{spec['name']}"


def _reachable(sess: Session, network: str, curl: str, log: Path) -> bool:
    """Retries one curl (its arguments, without `curl`) from inside the network until it succeeds."""
    limit = min(sess.s.limit("startup", 180), sess.left())
    tries = max(1, limit // 3)
    rc = sess.docker.run("e2e-probe", sess.s.images["zap"],
                         ["sh", "-c", f"for i in $(seq 1 {tries}); do curl -fsS -o /dev/null {curl} && exit 0; "
                                      f"sleep 3; done; exit 1"],
                         log=log, timeout=limit + 60, network=network, user=None, entrypoint="")
    return rc == 0


def _healthy(name: str, limit: int) -> bool:
    """A container with a HEALTHCHECK until it is healthy; one without, until it has run 20 s without exiting."""
    deadline = time.monotonic() + limit
    started = time.monotonic()
    while time.monotonic() < deadline:
        status = inspect(name, "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}")
        running = inspect(name, "{{.State.Running}}") == "true"
        if not running:
            return False
        if status == "healthy" or (status == "none" and time.monotonic() - started >= 20):
            return True
        time.sleep(3)
    return False


def judge(result: dict | None, rc: int) -> tuple[str, str]:
    """(outcome, reason) from the driver's result.json and exit code."""
    if rc == 124:
        return "error", "timed out"
    if not isinstance(result, dict) or not isinstance(result.get("steps"), list):
        return "error", f"the driver wrote no result.json (exit {rc})"
    by_name = {s.get("step"): s for s in result["steps"] if isinstance(s, dict)}
    for step in STEPS:
        rec = by_name.get(step) or {}
        if rec.get("status") != "passed":
            why = rec.get("error") or ("not run" if rec.get("status") in (None, "not_run") else rec.get("status"))
            return "error", f"e2e step {step}: {why}"
    if rc != 0:
        return "error", f"the driver exited {rc} with every step passed"
    if (result.get("csp_violations") or 0) > 0:      # reported after a step's last check (the binding is async)
        return "error", "Content-Security-Policy violation"
    return "ok", "passed"


def _read_result(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _empty_steps() -> list[dict]:
    return [{"step": s, "status": "not_run", "seconds": 0.0, "error": None} for s in STEPS]


# ------------------------------------------------------------------ the test

def execute(sess: Session, own: App | None):
    """Runs the test; returns (outcome, metrics, files, detail) as a stage does. Everything it starts is removed."""
    sess.dir.mkdir(parents=True, exist_ok=True)
    sess.work.mkdir(parents=True, exist_ok=True)
    log = sess.dir / "e2e.log"
    log.touch()
    sess.keep("e2e.log")
    net = f"gmshield-ci-{sess.id}-e2e"
    containers: dict[str, str] = {}             # log name -> container
    volumes: list[str] = []
    apps: list[App] = []
    result: dict | None = None
    outcome, reason = "error", ""
    try:
        try:
            apps = select_apps(sess, own)
            outcome, reason, result = _session(sess, apps, net, log, containers, volumes)
        except E2EError as e:
            outcome, reason = "error", str(e)
    finally:
        for name, cn in containers.items():
            try:
                container_logs(cn, sess.dir / f"{name}.log")
                sess.keep(f"{name}.log")
            except Exception:  # noqa: BLE001 - a missing log never stops the cleanup
                pass
        stages._remove(*containers.values())
        if volumes:
            sh(["docker", "volume", "rm", "-f", *volumes], None, 120)
        sh(["docker", "network", "rm", net], None, 60)
    shas = {a.service: a.sha for a in apps}
    final = {**(result or {"steps": _empty_steps()}), "outcome": outcome, "reason": reason, "shas": shas,
             "images": {a.service: a.image for a in apps}}
    (sess.dir / "result.json").write_text(json.dumps(final, indent=2))
    sess.keep("result.json")
    for f in sorted(sess.dir.glob("*-failed.png")):
        sess.keep(f.name)
    passed = sum(1 for s in final["steps"] if s.get("status") == "passed")
    metrics = {"shas": shas, "steps": final["steps"], "csp_violations": final.get("csp_violations", 0)}
    short = ", ".join(f"{k} {v[:8]}" for k, v in shas.items())
    if outcome == "ok":
        return "ok", metrics, list(sess.files), f"{passed}/{len(STEPS)} steps passed ({short})"
    metrics["error"] = reason
    return "error", metrics, list(sess.files), f"{reason}{f' ({short})' if short else ''}"


def _session(sess: Session, apps: list[App], net: str, log: Path, containers: dict, volumes: list):
    by = {a.service: a for a in apps}
    sess.left()
    frontend_src = by["frontend"].src / MESSAGES
    if not frontend_src.is_file():
        raise E2EError(f"the frontend has no {MESSAGES} at {by['frontend'].sha[:8]} (the driver's labels)")
    if not stages._network(sess, net, log):
        raise E2EError("cannot create the end-to-end network")
    for app in apps:
        made, err = stages._staging_volumes(sess, log, app.contract)
        volumes += made
        if err:
            raise E2EError(f"{app.service}: {err}")
    names, err = stages.start_services(sess, net, ["postgres", "redis"], "e2e", sess.dir, log)
    containers.update(zip(["postgres", "redis"], names))
    if err:
        raise E2EError(f"service {err}")
    sess.left()
    containers["stand-in-qdrant"] = _start(sess, qdrant_args(sess), net, log)
    containers["stand-in-ollama"] = _start(sess, ollama_args(sess, by["worker"]), net, log)
    if not _reachable(sess, net, f"'http://stand-in-qdrant:{QDRANT_PORT}/readyz'", log):
        raise E2EError("the stand-in Qdrant did not become ready")
    if not _reachable(sess, net, "-X POST -H 'Content-Type: application/json' --data '{\"input\":[\"ready\"]}' "
                                 f"'http://stand-in-ollama:{OLLAMA_PORT}/api/embed'", log):
        raise E2EError("the stand-in Ollama did not answer")
    for svc in ("backend", "worker", "frontend"):
        sess.left()
        app = by[svc]
        c = app.contract
        certs = None
        if c.certs:
            certs = stages.staging_certs(sess, [x for x in (ALIASES[svc], svc) if x], name=f"e2e-{svc}", log=log)
            if certs is None:
                raise E2EError(f"could not create the throwaway certificates of the {svc}")
        containers[svc] = cname(sess, svc)
        if sh(app_args(sess, app, net, certs), log, 120) != 0:
            raise E2EError(f"the {svc} failed to start")
        if c.http:
            ca = certs / "ca.crt" if c.health_scheme == "https" and certs else None
            host = ALIASES[svc] or svc
            url = f"{c.health_scheme}://{host}:{c.port}{c.health_path}"
            if not stages._probe(sess, net, url, log, ca):
                raise E2EError(f"the {svc} was not healthy at {c.health_path} within "
                               f"{sess.s.limit('startup', 180)}s")
    sess.left()
    if not _healthy(containers["worker"], min(sess.s.limit("startup", 180), sess.left())):
        raise E2EError(f"the worker was not healthy within {sess.s.limit('startup', 180)}s")
    inputs = sess.work / "in"
    inputs.mkdir(parents=True, exist_ok=True)
    (inputs / PDF_NAME).write_bytes(pdf_bytes())
    budget = max(sess.left() - 60, 1)
    (inputs / "config.json").write_text(json.dumps({
        "base": f"http://localhost:{FRONTEND_PORT}", "pdf": f"/in/{PDF_NAME}", "question": QUESTION,
        "username": USERNAME, "messages": "/messages/en.json", "out": "/out", "budget": budget}))
    inputs.chmod(0o755)
    for f in inputs.iterdir():
        f.chmod(0o644)
    spec = driver_args(sess, containers["frontend"], inputs, frontend_src)
    sess.log(f"e2e: driver started (budget {budget}s)")
    rc = sess.docker.run(spec["name"], spec["image"], spec["args"], log=sess.dir / "driver.log",
                         timeout=sess.left(), network=spec["network"], env=spec["env"], mounts=spec["mounts"])
    sess.keep("driver.log")
    result = _read_result(sess.dir / "result.json")
    outcome, reason = judge(result, rc)
    return outcome, reason, result


# ------------------------------------------------------------------ entry points

def stage(run: "Run"):
    """develop (full) of the backend, frontend or worker, after DAST: the run's image with the others' latest."""
    c = run.contract
    if c.service not in SERVICES:
        return "skipped", {}, [], "not an app of the end-to-end test"
    if not run.image_built:
        return "skipped", {}, [], "no image to test"
    sess = Session(s=run.s, id=run.id, docker=run.docker, dir=run.dir / "e2e", work=run.work / "e2e", rel="e2e/",
                   log=run.log)
    failed = build_driver(sess)
    if failed:
        return failed
    sess.deadline = time.monotonic() + run.s.limit("e2e", DEFAULT_LIMIT)
    own = App(c.service, run.repo.name, run.sha, run.local_image, c, run.src)
    return execute(sess, own)


def build_driver(sess: Session):
    """The driver image, before the deadline is set (`[limits] e2e` covers the test only): None when it is there,
    else the stage's error."""
    sess.dir.mkdir(parents=True, exist_ok=True)
    log = sess.dir / "e2e.log"
    log.touch()
    sess.keep("e2e.log")
    try:
        ensure_driver_image(sess, log)
    except E2EError as e:
        return "error", {"error": str(e)}, list(sess.files), str(e)
    return None


def folder_name(when: datetime) -> str:
    """The standalone result folder: UTC yyyy-mm-dd-HHMMSS, which housekeeping's RUN_ID never matches."""
    return f"{when.astimezone(timezone.utc):%Y-%m-%d-%H%M%S}"


def standalone(s: Settings) -> int:
    """`python3 -m gmshield_ci e2e`: the test against the latest develop image of all three apps, holding the poll
    lock (a poll's crash cleanup would remove its containers). Exit 0 only when every step passed."""
    from .pipeline import single_instance     # pipeline imports this module

    when = datetime.now(timezone.utc)
    run_id = f"e2e-{when:%Y%m%d-%H%M%S}"
    out = s.artifacts / "quality" / "e2e" / folder_name(when)
    docker = Docker(s.ci_slice, run_id, s.instance)
    sess = Session(s=s, id=run_id, docker=docker, dir=out, work=s.work / run_id,
                   log=lambda msg: print(msg, flush=True))
    with single_instance(s) as ok:
        if not ok:
            print("a pipeline run is in progress; try again when it ends")
            return 1
        t0 = time.monotonic()
        try:
            failed = build_driver(sess)
            if failed:
                outcome, metrics, _, detail = failed
            else:
                sess.deadline = time.monotonic() + s.limit("e2e", DEFAULT_LIMIT)
                outcome, metrics, _, detail = execute(sess, None)
        finally:
            docker.cleanup()
            shutil.rmtree(sess.work, ignore_errors=True)
    for step in metrics.get("steps") or []:
        print(f"  {step['step']:<15} {step['status']:<8} {step['seconds']:>7}s"
              f"{'  ' + step['error'] if step.get('error') else ''}")
    print(f"e2e: {'PASSED' if outcome == 'ok' else 'FAILED'}: {detail} in {round(time.monotonic() - t0)}s; "
          f"files in {out}")
    return 0 if outcome == "ok" else 1
