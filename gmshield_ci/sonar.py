"""SonarQube: on-demand server, one-time setup, and the analysis stage of the develop flow.

The server (sonarqube/compose.yaml, deployed to ~/gmshield-ci/sonarqube) is started when a run
first needs it and stopped when the poll ends, unless it was already running (for example while
someone reviews security hotspots in the web UI). A file lock serialises pipelines that share it.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import secrets
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

from .dockerops import sh

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import Run

SONAR_DIR = Path(os.environ.get("GMSHIELD_SONAR_DIR", str(Path.home() / "gmshield-ci" / "sonarqube")))
URL = "http://127.0.0.1:9000"          # from roberto-server itself
INTERNAL_URL = "http://sonarqube:9000"  # from containers on the gmshield-sonar network
NETWORK = "gmshield-sonar"
CREDS = SONAR_DIR / "credentials.env"   # SONAR_ADMIN_PASSWORD, SONAR_TOKEN (mode 600, never in git)
RATING = {"1.0": "A", "2.0": "B", "3.0": "C", "4.0": "D", "5.0": "E"}
MEASURES = ("bugs,vulnerabilities,code_smells,security_hotspots,coverage,duplicated_lines_density,ncloc,"
            "software_quality_security_rating,software_quality_reliability_rating,"
            "software_quality_maintainability_rating")


class SonarError(RuntimeError):
    pass


# ------------------------------------------------------------------ helpers

def _creds() -> dict:
    if not CREDS.is_file():
        return {}
    return dict(l.split("=", 1) for l in CREDS.read_text().splitlines() if "=" in l)


def _save_creds(d: dict) -> None:
    fd = os.open(CREDS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("".join(f"{k}={v}\n" for k, v in d.items()))


def api(method: str, path: str, params: dict | None = None, auth=None, timeout: int = 30) -> tuple[int, dict]:
    """auth: None, a token string (bearer) or a (user, password) tuple."""
    q = urllib.parse.urlencode(params or {})
    url = URL + path + (f"?{q}" if q and method == "GET" else "")
    data = q.encode() if q and method != "GET" else None
    req = urllib.request.Request(url, data=data, method=method)
    if isinstance(auth, tuple):
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
    elif auth:
        req.add_header("Authorization", f"Bearer {auth}")
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}
    except Exception:
        return -1, {}


def status() -> str | None:
    return api("GET", "/api/system/status", timeout=5)[1].get("status")


def token() -> str:
    tok = _creds().get("SONAR_TOKEN")
    if not tok:
        raise SonarError(f"no SonarQube token in {CREDS}; run: python3 -m gmshield_ci sonar-setup")
    return tok


# ------------------------------------------------------------------ server lifecycle

class Session:
    """The SonarQube server, held by this process from first use until close()."""
    _lock = None
    _started = False

    @classmethod
    def ensure_up(cls, log: Path | None = None, timeout: int = 600) -> None:
        if cls._lock is None:
            SONAR_DIR.mkdir(parents=True, exist_ok=True)
            fh = open(SONAR_DIR / ".lock", "w")
            deadline = time.monotonic() + 3600
            while True:
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        fh.close()
                        raise SonarError("SonarQube busy with another pipeline for over an hour")
                    time.sleep(10)
            cls._lock = fh
        if status() == "UP":
            return
        compose = SONAR_DIR / "compose.yaml"
        if not compose.is_file():
            raise SonarError(f"{compose} missing; deploy sonarqube/compose.yaml there")
        if sh(["docker", "compose", "-f", str(compose), "up", "-d"], log, 300) != 0:
            raise SonarError("docker compose up failed for SonarQube")
        cls._started = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if status() == "UP":
                return
            time.sleep(5)
        raise SonarError(f"SonarQube not up within {timeout}s")

    @classmethod
    def close(cls) -> None:
        """Stop the server if this process started it, then release the lock."""
        if cls._started:
            sh(["docker", "compose", "-f", str(SONAR_DIR / "compose.yaml"), "stop"], None, 300)
            cls._started = False
        if cls._lock is not None:
            fcntl.flock(cls._lock, fcntl.LOCK_UN)
            cls._lock.close()
            cls._lock = None


# ------------------------------------------------------------------ one-time setup

def setup(gates: dict) -> list[str]:
    """Idempotent: secure the admin account, create the pipeline token, install the quality gate."""
    done: list[str] = []
    Session.ensure_up()
    creds = _creds()
    if not creds.get("SONAR_ADMIN_PASSWORD"):
        new = secrets.token_urlsafe(18) + "Aa1!"      # meets SonarQube's complexity rules
        code, _ = api("POST", "/api/users/change_password",
                      {"login": "admin", "previousPassword": "admin", "password": new}, auth=("admin", "admin"))
        if code not in (200, 204):
            raise SonarError(f"cannot replace the default admin password (HTTP {code}); "
                             f"put SONAR_ADMIN_PASSWORD in {CREDS}")
        creds["SONAR_ADMIN_PASSWORD"] = new
        _save_creds(creds)
        done.append("default admin password replaced (saved in credentials.env)")
    admin = ("admin", creds["SONAR_ADMIN_PASSWORD"])
    tok = creds.get("SONAR_TOKEN")
    if not tok or api("GET", "/api/authentication/validate", auth=tok)[1].get("valid") is not True:
        code, d = api("POST", "/api/user_tokens/generate",
                      {"name": f"gmshield-pipeline-{time.strftime('%Y%m%d-%H%M%S')}", "type": "USER_TOKEN"},
                      auth=admin)
        if code != 200 or "token" not in d:
            raise SonarError(f"cannot create the pipeline token (HTTP {code})")
        creds["SONAR_TOKEN"] = d["token"]
        _save_creds(creds)
        done.append("pipeline token created")
    done += sync_gate(gates.get("sonar", {}), admin)
    return done


def sync_gate(cfg: dict, admin: tuple) -> list[str]:
    """Make the SonarQube gate match gates.toml exactly (gates.toml is the source of truth)."""
    done: list[str] = []
    name = cfg.get("quality_gate", "GMshield")
    want = {m: (op, str(err)) for m, op, err in cfg.get("conditions", [])}
    code, d = api("GET", "/api/qualitygates/show", {"name": name}, auth=admin)
    if code != 200:
        code, _ = api("POST", "/api/qualitygates/create", {"name": name}, auth=admin)
        if code != 200:
            raise SonarError(f"cannot create quality gate {name} (HTTP {code})")
        done.append(f"quality gate '{name}' created")
        code, d = api("GET", "/api/qualitygates/show", {"name": name}, auth=admin)  # new gates come pre-filled
    def call(path: str, params: dict, what: str) -> None:
        c, body = api("POST", path, params, auth=admin)
        if c not in (200, 204):
            msg = "; ".join(e.get("msg", "") for e in body.get("errors", [])) or f"HTTP {c}"
            raise SonarError(f"cannot {what}: {msg}")
        done.append(what)
    have = {c["metric"]: c for c in d.get("conditions", [])}
    for metric, c in have.items():
        if metric not in want:
            call("/api/qualitygates/delete_condition", {"id": c["id"]}, f"removed condition {metric}")
        elif (c.get("op"), str(c.get("error"))) != want[metric]:
            op, err = want[metric]
            call("/api/qualitygates/update_condition", {"id": c["id"], "metric": metric, "op": op, "error": err},
                 f"updated condition {metric} {op} {err}")
    for metric, (op, err) in want.items():
        if metric not in have:
            call("/api/qualitygates/create_condition", {"gateName": name, "metric": metric, "op": op, "error": err},
                 f"added condition {metric} {op} {err}")
    call("/api/qualitygates/set_as_default", {"name": name}, f"'{name}' is the default quality gate")
    return done


def delete_project(key: str) -> int:
    Session.ensure_up()
    admin = ("admin", _creds().get("SONAR_ADMIN_PASSWORD", ""))
    return api("POST", "/api/projects/delete", {"project": key}, auth=admin)[0]


# ------------------------------------------------------------------ the pipeline stage

def analyze(run: "Run"):
    """Scan the commit, wait for SonarQube's verdict, and return its quality gate result."""
    log = run.dir / "sonarqube.log"
    Session.ensure_up(log, run.s.limit("sonar_startup", 600))
    tok = token()
    key = run.repo.name
    reports = run.dir / "unit-tests"                      # files exported by the Dockerfile test-reports stage
    if reports.is_dir():
        shutil.copytree(reports, run.src / ".gmshield-reports", dirs_exist_ok=True)
    args = [f"-Dsonar.projectKey={key}", f"-Dsonar.projectName={key}", "-Dsonar.scm.disabled=true",
            "-Dsonar.working.directory=.scannerwork", f"-Dsonar.analysis.commit={run.sha}"]
    if (run.src / ".gmshield-reports" / "classes").is_dir():
        args.append("-Dsonar.java.binaries=.gmshield-reports/classes")
    cache = run.s.cache / "sonar"
    cache.mkdir(parents=True, exist_ok=True)
    rc = run.docker.run("sonar-scanner", run.s.images["sonar_scanner"], args, log=log,
                        timeout=run.s.limit("sonar", 1800), network=NETWORK, workdir="/usr/src",
                        mounts=[(run.src, "/usr/src", "rw"), (cache, "/cache", "rw")],
                        env={"SONAR_HOST_URL": INTERNAL_URL, "SONAR_USER_HOME": "/cache", "HOME": "/tmp"},
                        secret_env={"SONAR_TOKEN": tok})
    task_file = run.src / ".scannerwork" / "report-task.txt"
    if rc != 0 or not task_file.is_file():
        return "error", {"error": f"sonar-scanner exit {rc}"}, ["sonarqube.log"], f"scanner failed (exit {rc})"
    task = dict(l.split("=", 1) for l in task_file.read_text().splitlines() if "=" in l)
    deadline = time.monotonic() + run.s.limit("sonar_processing", 600)
    while True:
        _, d = api("GET", "/api/ce/task", {"id": task.get("ceTaskId", "")}, auth=tok)
        state = d.get("task", {}).get("status")
        if state in ("SUCCESS", "FAILED", "CANCELED"):
            break
        if time.monotonic() > deadline:
            return "error", {"error": "SonarQube did not finish processing in time"}, ["sonarqube.log"], "timeout"
        time.sleep(3)
    if state != "SUCCESS":
        return "error", {"error": f"SonarQube processing {state}"}, ["sonarqube.log"], f"processing {state}"
    _, qg = api("GET", "/api/qualitygates/project_status", {"analysisId": d["task"].get("analysisId", "")}, auth=tok)
    ps = qg.get("projectStatus", {})
    _, ms = api("GET", "/api/measures/component", {"component": key, "metricKeys": MEASURES}, auth=tok)
    measures = {m["metric"]: m.get("value") for m in ms.get("component", {}).get("measures", [])}
    for k in list(measures):
        if k.endswith("_rating"):
            measures[k] = RATING.get(str(measures[k]), measures[k])
    _, hs = api("GET", "/api/hotspots/search", {"project": key, "status": "TO_REVIEW", "ps": 1}, auth=tok)
    to_review = int(hs.get("paging", {}).get("total", 0) or 0)
    dashboard = task.get("dashboardUrl", "").replace(INTERNAL_URL, "http://localhost:9000")
    failed = [f"{c.get('metricKey')} = {c.get('actualValue')} (fails when {c.get('comparator')} "
              f"{c.get('errorThreshold')})" for c in ps.get("conditions", []) if c.get("status") == "ERROR"]
    report = {"quality_gate": ps.get("status", "NONE"), "conditions": ps.get("conditions", []),
              "measures": measures, "hotspots_to_review": to_review, "dashboard": dashboard,
              "ce_task": task.get("ceTaskId"), "analysis": d["task"].get("analysisId")}
    (run.dir / "sonarqube.json").write_text(json.dumps(report, indent=2))
    top = failed + ([f"{to_review} security hotspot(s) need a decision in SonarQube: {dashboard}"] if to_review else [])
    metrics = {"status": report["quality_gate"], "failed": failed, "measures": measures,
               "hotspots_to_review": to_review, "dashboard": dashboard, "top": top}
    m = measures
    detail = (f"quality gate {report['quality_gate']}; security {m.get('software_quality_security_rating', '-')}, "
              f"reliability {m.get('software_quality_reliability_rating', '-')}, "
              f"maintainability {m.get('software_quality_maintainability_rating', '-')}, "
              f"hotspots to review {to_review}")
    return "ok", metrics, ["sonarqube.json", "sonarqube.log"], detail
