#!/usr/bin/env python3
"""Fetch GMshield CI/CD results from roberto-server into the docs folder and show them.

Run by hand; nothing is scheduled. Every pipeline run becomes one folder, separated by branch:

  docs/ci-cd/<branch>/release-<branch>-<YYYYMMDDTHHMMSSZ>/   (start time, UTC)
      RELEASE.md     release information: repository, commit, result, every test and its report
      release.json   the same, machine-readable
      artifacts/     every report and log of that run (Gitleaks, Semgrep, SonarQube, Trivy, SBOMs, ZAP)

  gmshield-results                                  latest result of every repo and branch
  gmshield-results -b develop                       most recent develop run of every repo, test by test
  gmshield-results -b main -r backend               most recent main run of one repo
  gmshield-results -b develop -t sonarqube          one test, for every repo (names: --tests)
  gmshield-results --release <folder> [-t dast]     one specific past run
  gmshield-results --list [-b main] [-r backend]    every release folder, newest first
  gmshield-results -b develop -r backend --rerun    re-run it on the server first
  gmshield-results --no-fetch ...                   use what is already in docs (server offline)

Exit code: 0 everything shown passed, 1 something failed or was blocked, 2 nothing to show.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

DOCS = Path(os.environ.get("GMSHIELD_DOCS", Path.home() / "agentic-RPG" / "docs"))
CICD = DOCS / "ci-cd"                                   # ci-cd/develop/..., ci-cd/main/...
CACHE = Path(os.environ.get("GMSHIELD_CACHE", Path.home() / ".cache" / "gmshield" / "artifacts"))
HOST = os.environ.get("GMSHIELD_SERVER", "roberto-server")
ORG = "GMshield"
SSH = ["ssh", "-o", "ClearAllForwardings=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")   # repo, branch and host names: nothing a shell interprets
MARK = {"passed": "PASS", "failed": "FAIL", "skipped": "skip", "blocked": "BLOCKED"}
TESTS = {  # test name -> pipeline stage keys (develop and main share names where they mean the same)
    "unit-tests": ["unit_tests"], "secrets": ["secrets"], "semgrep": ["sast"], "sca": ["sca_iac:sca"],
    "iac": ["sca_iac:iac"], "sonarqube": ["sonar"], "image": ["image"], "dast": ["dast", "dast_prod"],
    "promotion": ["promotion"], "publish": ["publish"], "deploy": ["deploy"], "release": ["release"],
}
VERDICT = {
    ("develop", "passed"): "quality gate passed: this code may be merged to main",
    ("develop", "failed"): "blocked by the quality gate",
    ("main", "passed"): "deployed and released",
    ("main", "failed"): "not released: a production check failed",
    ("main", "blocked"): "not deployed: this code had not passed develop",
}


# ------------------------------------------------------------------ fetch and organise

def fetch() -> bool:
    CACHE.mkdir(parents=True, exist_ok=True)
    rc = subprocess.run(["rsync", "-a", "--timeout=60", "-e", " ".join(SSH),
                         f"{HOST}:gmshield-ci/artifacts/", f"{CACHE}/"]).returncode
    if rc != 0:
        print(f"warning: could not fetch from {HOST} (rsync exit {rc}); showing what is already in docs",
              file=sys.stderr)
    return rc == 0


def folder_name(s: dict) -> str:
    started = datetime.fromisoformat(s["started"])
    return f"release-{s['branch']}-{started:%Y%m%dT%H%M%SZ}"


def organise() -> int:
    """Turn each finished run in the cache into docs/ci-cd/<branch>/release-<branch>-<datetime>/.
    Returns how many are new."""
    known = {json.loads(p.read_text()).get("run"): p.parent for p in CICD.glob("*/release-*/release.json")}
    new = 0
    for summary in sorted(CACHE.glob("GMshield-*/*/*/summary.json")):   # summary.json exists = run finished
        s = json.loads(summary.read_text())
        if s.get("run") in known:
            continue
        name = folder_name(s)
        if (CICD / s["branch"] / name).exists():                       # two runs in the same second
            name += "-" + s["repo"].lower().removeprefix("gmshield-")
        dest = CICD / s["branch"] / name
        shutil.copytree(summary.parent, dest / "artifacts")
        s["folder"] = f"ci-cd/{s['branch']}/{name}"                  # relative to docs
        tag = s.get("release")
        if tag and (summary.parents[2] / "releases" / tag / "release.json").is_file():
            s["release_record"] = json.loads((summary.parents[2] / "releases" / tag / "release.json").read_text())
        (dest / "release.json").write_text(json.dumps(s, indent=2))
        (dest / "RELEASE.md").write_text(release_md(s))
        known[s["run"]] = dest
        new += 1
    return new


def _dur(sec: float) -> str:
    sec = int(sec or 0)
    return f"{sec // 60}m {sec % 60:02d}s" if sec >= 60 else f"{sec}s"


def _reports(st: dict) -> list[str]:
    return [f for f in st.get("files", []) if not f.startswith("..")]


def _warnings(s: dict) -> list[tuple[str, str]]:
    """(test title, warning) pairs of a run, without repeats. Warnings never change the result."""
    return list(dict.fromkeys((st["title"], w) for st in s.get("stages", []) for w in st.get("warnings", [])))


def release_md(s: dict) -> str:
    repo, branch, sha, c = s["repo"], s["branch"], s["sha"], s.get("commit", {})
    gh = repo.startswith("GMshield-")
    started = datetime.fromisoformat(s["started"])
    verdict = VERDICT.get((branch, s["result"]), s["result"])
    deployed = any(st["key"] == "deploy" and st["status"] == "passed" for st in s.get("stages", []))
    if branch == "main" and s["result"] == "passed" and not deployed:
        verdict = "released (nothing to deploy: no Dockerfile yet)"
    commit = f"[`{sha[:8]}`](https://github.com/{ORG}/{repo}/commit/{sha})" if gh else f"`{sha[:8]}`"
    warnings = _warnings(s)
    warned = f" {len(warnings)} warning{'s' if len(warnings) != 1 else ''}, listed below." if warnings else ""
    lines = [f"# {repo} · {branch} · {started:%Y-%m-%d %H:%M:%S} UTC", "",
             f"**Result: {s['result'].upper()}**, {verdict}.{warned}", "",
             "| | |", "|---|---|",
             f"| Repository | {f'[{repo}](https://github.com/{ORG}/{repo})' if gh else repo} |",
             f"| Branch | {branch} |",
             f"| Commit | {commit} {c.get('subject', '')} |",
             f"| Author, commit date | {c.get('author', '')}, {c.get('date', '')} |",
             f"| Pipeline run | `{s['run']}` on {s.get('host', '?')}, {s.get('mode', 'full')} run, {_dur(s.get('seconds'))} |"]
    if s.get("release"):
        tag = s["release"]
        lines.append(f"| Release tag | {f'[{tag}](https://github.com/{ORG}/{repo}/releases/tag/{tag})' if gh else tag} |")
    image = (s.get("release_record") or {}).get("image")
    if image:
        lines.append(f"| Production image | `{image}` |")
    lines += ["", "## Test results", "", "| Test | Result | Details | Threshold | Reports |", "|---|---|---|---|---|"]
    for st in s.get("stages", []):
        links = ", ".join(f"[{Path(f).name or f}](artifacts/{f})" for f in _reports(st)) or "-"
        lines.append(f"| {st['title']} | {MARK.get(st['status'], st['status'])} | "
                     f"{st.get('detail', '').replace('|', '/')} | {st.get('threshold', '-')} | {links} |")
    reasons = [(st["title"], r) for st in s.get("stages", []) if st["status"] == "failed" for r in st.get("reasons", [])]
    if reasons or s.get("notes"):
        lines += ["", "## Outcome", ""]
        lines += [f"- **{t}:** {r}" for t, r in reasons]
        lines += [f"- {n}" for n in s.get("notes", [])]
    if warnings:
        lines += ["", "## Warnings", "", "Warnings do not change the result.", ""]
        lines += [f"- **{t}:** {w}" for t, w in warnings]
    lines += ["", "## Artifacts", "",
              "Every report and log of this run is in [artifacts/](artifacts/); the pipeline's own summary is "
              "[artifacts/summary.md](artifacts/summary.md) and its full log [artifacts/pipeline.log](artifacts/pipeline.log).", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ queries

def releases(branch: str | None = None, repo: str | None = None) -> list[dict]:
    out = []
    for p in CICD.glob("*/release-*/release.json"):
        s = json.loads(p.read_text())
        if branch and s["branch"] != branch:
            continue
        if repo and s["repo"].lower() not in (repo.lower(), f"gmshield-{repo.lower()}"):
            continue
        out.append(s)
    return sorted(out, key=lambda s: s["started"], reverse=True)


def latest(rows: list[dict]) -> list[dict]:
    """Most recent full run per (repo, branch); light runs only if a branch has nothing else."""
    best: dict[tuple, dict] = {}
    for s in sorted(rows, key=lambda s: (s.get("mode") == "full", s["started"])):
        best[(s["repo"], s["branch"])] = s
    return sorted(best.values(), key=lambda s: (s["repo"], s["branch"]))


def show_table(rows: list[dict]) -> None:
    print(f"{'Repo':<20} {'Branch':<8} {'Result':<8} {'Warn':<5} {'Commit':<9} Release folder (docs/)")
    for s in rows:
        print(f"{s['repo']:<20} {s['branch']:<8} {s['result'].upper():<8} {str(len(_warnings(s)) or '-'):<5} "
              f"{s['sha'][:8]:<9} {s['folder']}")


def show_detail(s: dict, test: str | None) -> None:
    c = s.get("commit", {})
    print(f"\n{s['repo']} · {s['branch']} · {s['sha'][:8]} · {s['result'].upper()}"
          f"{' · release ' + s['release'] if s.get('release') else ''}")
    print(f"  {c.get('subject', '')} ({c.get('author', '')}); run {s['run']}")
    keys = TESTS.get(test, []) if test else None
    shown = 0
    for st in s.get("stages", []):
        if keys is not None and st["key"] not in keys:
            continue
        shown += 1
        print(f"  {MARK.get(st['status'], st['status']):<5} {st['title']:<40} {st.get('detail', '')[:90]}")
        if test:
            print(f"        threshold: {st.get('threshold', '-')}")
        for r in st.get("reasons", []) if st["status"] == "failed" else []:
            print(f"        -> {r}")
        for w in st.get("warnings", []):
            print(f"        warning: {w}")
        if test:
            for f in _reports(st):
                print(f"        report: {DOCS / s['folder'] / 'artifacts' / f}")
    if test and not shown:
        print(f"  (no '{test}' test in this {s['branch']} run)")
    for note in ([] if test else s.get("notes", [])):
        print(f"  note: {note}")
    print(f"  release info: {DOCS / s['folder'] / 'RELEASE.md'}")


def rerun(repo: str, branch: str) -> None:
    # The remote side runs this through a shell: accept only plain names and quote them anyway.
    for value in (repo, branch, HOST):
        if not NAME.fullmatch(value):
            sys.exit(f"refusing unsafe name: {value!r}")
    remote = (f"cd ~/gmshield-ci/runner && python3 -m gmshield_ci run "
              f"{shlex.quote(repo)} {shlex.quote(branch)}")
    print(f"re-running {repo} {branch} on {HOST} (this can take several minutes)...", flush=True)
    subprocess.run(SSH + [shlex.quote(HOST), remote])


def main() -> int:
    p = argparse.ArgumentParser(prog="gmshield-results", description=__doc__.split("\n\n")[0])
    p.add_argument("-b", "--branch", choices=["develop", "main"], help="most recent run of this branch")
    p.add_argument("-r", "--repo", help="backend, frontend, worker, pipeline (or the full name)")
    p.add_argument("-t", "--test", choices=sorted(TESTS), help="show one test (with its threshold and reports)")
    p.add_argument("--release", help="show one release folder, e.g. release-develop-20261109T192101Z")
    p.add_argument("--list", action="store_true", help="list release folders, newest first")
    p.add_argument("--tests", action="store_true", help="list the test names for -t")
    p.add_argument("--rerun", action="store_true", help="re-run --branch of --repo on the server first")
    p.add_argument("--no-fetch", action="store_true", help="do not contact the server")
    a = p.parse_args()
    if a.tests:
        for name, keys in TESTS.items():
            print(f"{name:<11} stage {', '.join(keys)}")
        return 0
    if a.rerun:
        if not (a.repo and a.branch):
            p.error("--rerun needs both --repo and --branch")
        rerun(a.repo, a.branch)
    if not a.no_fetch and fetch():
        new = organise()
        print(f"fetched from {HOST}: {new} new release folder(s) in {CICD}")
    if a.release:
        found = [f for f in CICD.glob(f"*/{Path(a.release).name}/release.json")] if NAME.fullmatch(
            Path(a.release).name) else []
        if not found:
            print(f"no release folder {a.release} in {CICD}")
            return 2
        s = json.loads(found[0].read_text())
        show_detail(s, a.test)
        return 0 if s["result"] == "passed" else 1
    rows = releases(a.branch, a.repo)
    if not rows:
        print("nothing to show" + (f" for {a.repo}" if a.repo else "") + (f" on {a.branch}" if a.branch else ""))
        return 2
    if a.list:
        print(f"{'Release folder (in docs/ci-cd/<branch>/)':<44} {'Repo':<20} {'Result':<8} {'Mode':<6} Commit")
        for s in rows:
            print(f"{Path(s['folder']).name:<44} {s['repo']:<20} {s['result'].upper():<8} {s.get('mode', ''):<6} "
                  f"{s['sha'][:8]} {s.get('commit', {}).get('subject', '')[:50]}")
        return 0
    shown = latest(rows)
    if a.branch or a.test:
        for s in shown:
            show_detail(s, a.test)
    else:
        print()
        show_table(shown)
    return 0 if all(s["result"] == "passed" for s in shown) else 1


if __name__ == "__main__":
    sys.exit(main())
