"""Orchestration: poll GitHub, run the develop or main flow, keep state, write reports."""
from __future__ import annotations

import fcntl
import json
import shutil
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import github, gitops, report, stages
from .config import Contract, Repo, Settings, load_contract
from .dockerops import Docker, cleanup_label, prune_images, sh

TITLES = {"sca": "SCA & SBOM (Trivy)", "iac": "IaC misconfiguration (Trivy)"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def log(msg: str) -> None:
    print(f"{now():%Y-%m-%d %H:%M:%S}Z {msg}", flush=True)


class Run:
    def __init__(self, s: Settings, repo: Repo, branch: str, sha: str, mirror: Path, mode: str,
                 old: str | None = None, push: list[str] | None = None):
        self.s, self.repo, self.branch, self.sha, self.mirror = s, repo, branch, sha, mirror
        self.mode, self.old, self.push = mode, old, push or [sha]
        self.short = sha[:8]
        self.started = now()
        self.id = f"{self.started:%Y%m%d-%H%M%S}-{self.short}"
        self.dir = s.artifacts / repo.name / branch / self.id
        self.work = s.work / self.id
        self.src = self.work / "src"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.work.mkdir(parents=True, exist_ok=True)
        self.records: list[stages.Record] = []
        self.lock = threading.Lock()
        self.titles = TITLES
        self.docker = Docker(s.ci_slice, self.id)
        self.contract = Contract()
        self.tree = ""
        self.commit: dict = {}
        self.log_opts = sha
        self.image_built = self.deployed = self.rolled_back = False
        self.previous_image: str | None = None
        self.promotions: dict = {}
        self.result = "running"
        self.notes: list[str] = []
        self.release_tag: str | None = None

    # names derived from the contract
    @property
    def local_image(self) -> str:
        return f"gmshield-ci/{self.contract.service}:{self.sha}"

    @property
    def prod_image(self) -> str:
        return f"{self.s.registry}/gmshield-{self.contract.service}:{self.sha}"

    @property
    def prod_name(self) -> str:
        return f"gmshield-{self.contract.service}"

    def log(self, msg: str) -> None:
        line = f"{now():%H:%M:%S}Z [{self.repo.name}/{self.branch}@{self.short}] {msg}"
        print(line, flush=True)
        with open(self.dir / "pipeline.log", "a") as fh:
            fh.write(line + "\n")


# ------------------------------------------------------------------ state

def _read(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str))
    tmp.replace(path)          # atomic: a crash never leaves a half-written state file


@contextmanager
def single_instance(s: Settings):
    s.state_dir.mkdir(parents=True, exist_ok=True)
    fh = open(s.state_dir / "poll.lock", "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fh.close()
        yield False
        return
    try:
        yield True
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


# ------------------------------------------------------------------ stages shared by flows

def _resolve(run: Run):
    gitops.export(run.mirror, run.sha, run.src)
    run.contract = load_contract(run.src, run.repo.name)
    run.tree = gitops.tree(run.mirror, run.sha)
    run.commit = gitops.commit_info(run.mirror, run.sha)
    c = run.contract
    m = {"flow": f"{run.branch} ({run.mode})", "tree": run.tree, "contract": c.present,
         "dockerfile": c.has_dockerfile, "stages": c.dockerfile_stages, "service": c.service,
         "http_port": c.port, "commits_in_push": len(run.push)}
    detail = (f"contract {'found' if c.present else 'missing'}, Dockerfile {'found' if c.has_dockerfile else 'missing'}"
              f", {len(run.push)} commit(s) in push")
    return "ok", m, [], detail


def _source_checks(run: Run, with_tests: bool) -> None:
    jobs = [("secrets", "Secret scan (Gitleaks)", "secrets", stages.secrets),
            ("sast", "SAST (Semgrep)", "sast", stages.sast),
            ("sca_iac", "SCA, SBOM & IaC (Trivy)", ["sca", "iac"], stages.sca_iac)]
    if with_tests:
        jobs.insert(0, ("unit_tests", "Unit tests", "unit_tests", stages.unit_tests))
    with ThreadPoolExecutor(max_workers=2) as ex:
        for f in [ex.submit(stages.execute, run, *j) for j in jobs]:
            f.result()


def _passed(run: Run) -> bool:
    return all(r.status in ("passed", "skipped") for r in run.records)


# ------------------------------------------------------------------ flows

def develop_flow(run: Run) -> None:
    """develop: unit tests + SAST + secrets + SCA/IaC, image build+scan, active DAST, then the gate."""
    if run.mode == "light":
        run.log_opts = f"{run.sha}^!"
        _source_checks(run, with_tests=False)
    else:
        if run.old and gitops.is_ancestor(run.mirror, run.old, run.sha):
            run.log_opts = f"{run.old}..{run.sha}"
        _source_checks(run, with_tests=True)
        stages.execute(run, "image", "Container image (build, SBOM & scan)", "image", stages.image)
        stages.execute(run, "dast", "DAST (OWASP ZAP, active, staging)", "dast_develop", stages.dast_staging)
    run.result = "passed" if _passed(run) else "failed"
    if run.mode == "full" and run.result == "passed":
        promos = _read(run.s.state_dir / "promotions.json", {})
        promos.setdefault(run.repo.name, {})[run.tree] = {"sha": run.sha, "run": run.id, "at": now().isoformat()}
        _write(run.s.state_dir / "promotions.json", promos)
        run.notes.append("Quality gate passed: this exact code may now be merged to main.")


def main_flow(run: Run) -> None:
    """main: promotion check, rebuild + image gate, publish, deploy, passive DAST, rollback or release."""
    run.promotions = _read(run.s.state_dir / "promotions.json", {})
    [promo] = stages.execute(run, "promotion", "Promotion check (passed develop)", "promotion", stages.promotion)
    if promo.status != "passed":
        run.result = "blocked"
        run.notes.append("Not deployed: merge to main only code that passed the develop pipeline.")
        return
    [img] = stages.execute(run, "image", "Container image (build, SBOM & scan)", "image", stages.image)
    if img.status == "failed":
        run.result = "failed"
        run.notes.append("Not deployed: the production image failed its gate.")
        return
    if run.contract.has_dockerfile:
        [pub] = stages.execute(run, "publish", "Publish image (local registry)", None, stages.publish)
        if pub.status == "passed":
            stages.execute(run, "deploy", "Deploy (prd)", None, stages.deploy)
        if run.deployed:
            [dast] = stages.execute(run, "dast_prod", "DAST post-deploy (prd, passive)", "dast_main",
                                    stages.dast_production)
            if dast.status == "failed" and run.s.gates.get("dast_main", {}).get("rollback_on_fail", True):
                msg = stages.rollback(run, run.dir / "deploy.log")
                run.notes.append(f"Post-deploy DAST failed: {msg}.")
    run.result = "passed" if _passed(run) else "failed"
    if run.result == "passed":
        stages.mark_prod(run)
        stages.execute(run, "release", "Release", None, _release)


def _release(run: Run):
    tag = f"r{run.started:%Y.%m.%d-%H%M}-{run.short}"
    run.release_tag = tag
    rel = run.s.artifacts / run.repo.name / "releases" / tag
    rel.mkdir(parents=True, exist_ok=True)
    link = rel / "run"
    if not link.exists():
        link.symlink_to(Path("..") / ".." / run.branch / run.id)
    info = {"tag": tag, "repo": run.repo.name, "sha": run.sha, "tree": run.tree, "commit": run.commit,
            "image": run.prod_image if run.image_built else None, "run": run.id, "at": now().isoformat()}
    stages.write_json(rel / "release.json", info)
    (rel / "RELEASE.md").write_text(
        f"# {run.repo.name} {tag}\n\n- Commit: `{run.sha}` {run.commit.get('subject', '')}\n"
        f"- Image: `{info['image'] or 'none (no Dockerfile)'}`\n- Pipeline run: [run/summary.md](run/summary.md)\n")
    gh = github.create_release(run.s.org, run.repo.name, tag, run.sha, run.commit.get("subject", ""))
    return "ok", {"tag": tag, "github": gh}, [f"../../releases/{tag}/RELEASE.md"], \
        f"{tag}{' (GitHub release created)' if gh == 'created' else ''}"


def execute_run(s: Settings, repo: Repo, branch: str, sha: str, mirror: Path, mode: str = "full",
                old: str | None = None, push: list[str] | None = None) -> Run:
    run = Run(s, repo, branch, sha, mirror, mode, old, push)
    t0 = time.monotonic()
    run.log(f"run {run.id} started ({mode})")
    context = f"gmshield-ci/{branch}"
    if mode == "full":
        github.status(s.org, repo.name, sha, "pending", context, f"roberto-server pipeline running ({run.id})")
    try:
        [res] = stages.execute(run, "resolve", "Resolve flow", None, _resolve)
        if res.status != "passed":
            run.result = "failed"
        elif branch == "main":
            main_flow(run)
        else:
            develop_flow(run)
    except Exception:
        run.result = "failed"
        run.log("pipeline crashed:\n" + traceback.format_exc())
    finally:
        run.seconds = round(time.monotonic() - t0, 1)
        try:
            report.write_run(run)
        except Exception:
            run.log("report failed:\n" + traceback.format_exc())
        run.docker.cleanup()
        shutil.rmtree(run.work, ignore_errors=True)
        if run.contract.service:
            prune_images(f"gmshield-ci/{run.contract.service}", s.limit("keep_images_per_service", 3))
        sh(["docker", "image", "prune", "-f", "--filter", "dangling=true"], None, 300)
    if mode == "full":
        state = {"passed": "success", "blocked": "failure"}.get(run.result, "failure")
        github.status(s.org, repo.name, sha, state, context,
                      f"{run.result.upper()} on roberto-server ({run.id})"[:140])
    run.log(f"run {run.id} finished: {run.result.upper()} in {run.seconds}s")
    return run


# ------------------------------------------------------------------ polling

def process(s: Settings, repo: Repo, branch: str, mirror: Path, last: str | None, sha: str) -> Run:
    if branch == "develop":
        push = gitops.new_commits(mirror, last, sha)
        limit = s.limit("max_intermediate_commits", 20)
        for c in push[:-1][-limit:]:          # every earlier commit of the push gets a light scan
            execute_run(s, repo, branch, c, mirror, "light", push=[c])
        return execute_run(s, repo, branch, sha, mirror, "full", old=last, push=push)
    return execute_run(s, repo, branch, sha, mirror, "full", old=last)


def poll(s: Settings) -> int:
    with single_instance(s) as ok:
        if not ok:
            log("another pipeline run is in progress; skipping this poll")
            return 0
        cleanup_label("gmshield-ci=1")        # leftovers of a crashed run, if any
        state_file = s.state_dir / "state.json"
        state = _read(state_file, {})
        for repo in s.repos:
            try:
                mirror = gitops.sync_mirror(repo, s.mirrors)
            except gitops.GitError as e:
                log(f"{repo.name}: cannot sync mirror: {e}")
                continue
            for branch in s.branches:
                sha = gitops.head(mirror, branch)
                last = state.get(repo.name, {}).get(branch, {}).get("sha")
                if not sha or sha == last:
                    continue
                log(f"{repo.name}/{branch}: {last[:8] if last else 'new'} -> {sha[:8]}")
                run = process(s, repo, branch, mirror, last, sha)
                state.setdefault(repo.name, {})[branch] = {"sha": sha, "run": run.id, "result": run.result,
                                                          "at": now().isoformat()}
                _write(state_file, state)
        return 0


def manual_run(s: Settings, repo_name: str, branch: str, sha: str | None = None) -> int:
    repo = next((r for r in s.repos if r.name.lower() == repo_name.lower()), None)
    if not repo:
        log(f"unknown repo {repo_name}; known: {', '.join(r.name for r in s.repos)}")
        return 2
    with single_instance(s) as ok:
        if not ok:
            log("another pipeline run is in progress; try again later")
            return 1
        mirror = gitops.sync_mirror(repo, s.mirrors)
        target = sha or gitops.head(mirror, branch)
        if not target:
            log(f"{repo.name} has no branch {branch}")
            return 2
        run = execute_run(s, repo, branch, target, mirror, "full")
        return 0 if run.result == "passed" else 1
