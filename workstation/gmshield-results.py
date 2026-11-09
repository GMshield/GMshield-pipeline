#!/usr/bin/env python3
"""Fetch GMshield CI/CD results from roberto-server and show them. Run by hand; nothing is scheduled.

  gmshield-results                          latest result of every repo and branch
  gmshield-results -b develop               most recent develop run of every repo, stage by stage
  gmshield-results -b main -r backend       most recent main run of one repo, stage by stage
  gmshield-results -b develop -r backend --rerun   re-run that branch on the server first
                                                   (e.g. after reviewing SonarQube hotspots)
  gmshield-results --no-fetch ...           use the local copy only (server offline)

Every fetch copies all new reports into docs/artifacts (additive; nothing local is deleted), so
the folder keeps the artifacts of every commit and release. Exit code: 0 all shown runs passed,
1 something failed or was blocked, 2 nothing to show.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

DEST = Path(os.environ.get("GMSHIELD_ARTIFACTS", Path.home() / "agentic-RPG" / "docs" / "artifacts"))
HOST = os.environ.get("GMSHIELD_SERVER", "roberto-server")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")   # repo, branch and host names: nothing a shell interprets
SSH = ["ssh", "-o", "ClearAllForwardings=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
MARK = {"passed": "PASS", "failed": "FAIL", "skipped": "skip", "blocked": "BLOCKED"}


def fetch() -> int | None:
    before = set(DEST.glob("*/*/*/summary.json"))
    DEST.mkdir(parents=True, exist_ok=True)
    rc = subprocess.run(["rsync", "-a", "--timeout=60", "-e", " ".join(SSH),
                         f"{HOST}:gmshield-ci/artifacts/", f"{DEST}/"]).returncode
    if rc != 0:
        print(f"warning: could not fetch from {HOST} (rsync exit {rc}); showing the local copy", file=sys.stderr)
        return None
    return len(set(DEST.glob("*/*/*/summary.json")) - before)


def rerun(repo: str, branch: str) -> None:
    # The remote side runs this through a shell: accept only plain names and quote them anyway.
    for value in (repo, branch, HOST):
        if not NAME.fullmatch(value):
            sys.exit(f"refusing unsafe name: {value!r}")
    remote = (f"cd ~/gmshield-ci/runner && python3 -m gmshield_ci run "
              f"{shlex.quote(repo)} {shlex.quote(branch)}")
    print(f"re-running {repo} {branch} on {HOST} (this can take several minutes)...", flush=True)
    subprocess.run(SSH + [shlex.quote(HOST), remote])


def latest(repo_dir: Path, branch: str) -> dict | None:
    hist = repo_dir / branch / "history.jsonl"
    if not hist.is_file():
        return None
    rows = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()]
    full = [r for r in rows if r.get("mode") == "full"] or rows
    return full[-1] if full else None


def repos(filter_name: str | None) -> list[Path]:
    dirs = sorted(p for p in DEST.glob("GMshield-*") if p.is_dir())
    if filter_name:
        n = filter_name.lower()
        dirs = [p for p in dirs if p.name.lower() in (n, f"gmshield-{n}")]
    return dirs


def show_table(dirs: list[Path], branches: list[str]) -> list[str]:
    results = []
    print(f"{'Repo':<20} {'Branch':<8} {'Result':<8} {'Commit':<9} {'When (UTC)':<17} Run")
    for d in dirs:
        for b in branches:
            r = latest(d, b)
            if not r:
                continue
            results.append(r["result"])
            print(f"{d.name:<20} {b:<8} {r['result'].upper():<8} {r['sha'][:8]:<9} "
                  f"{r['started'][:16].replace('T', ' '):<17} {r['run']}")
    return results


def show_detail(dirs: list[Path], branch: str) -> list[str]:
    results = []
    for d in dirs:
        r = latest(d, branch)
        if not r:
            print(f"\n{d.name} {branch}: no runs yet")
            continue
        run_dir = d / branch / r["run"]
        s = json.loads((run_dir / "summary.json").read_text())
        results.append(s["result"])
        c = s.get("commit", {})
        print(f"\n{d.name} · {branch} · {s['sha'][:8]} · {s['result'].upper()}"
              f"{' · release ' + s['release'] if s.get('release') else ''}")
        print(f"  {c.get('subject', '')} ({c.get('author', '')}, {s['started'][:16].replace('T', ' ')} UTC)")
        for st in s["stages"]:
            print(f"  {MARK.get(st['status'], st['status']):<5} {st['title']:<40} {st['detail'][:90]}")
            for reason in st.get("reasons", []) if st["status"] == "failed" else []:
                print(f"        -> {reason}")
        for note in s.get("notes", []):
            print(f"  note: {note}")
        print(f"  report: {run_dir / 'summary.md'}")
    return results


def main() -> int:
    p = argparse.ArgumentParser(prog="gmshield-results", description=__doc__.split("\n\n")[0])
    p.add_argument("-b", "--branch", choices=["develop", "main"], help="show the most recent run of this branch")
    p.add_argument("-r", "--repo", help="backend, frontend, worker, pipeline (or the full name)")
    p.add_argument("--rerun", action="store_true", help="re-run --branch of --repo on the server first")
    p.add_argument("--no-fetch", action="store_true", help="do not contact the server")
    a = p.parse_args()
    if a.rerun:
        if not (a.repo and a.branch):
            p.error("--rerun needs both --repo and --branch")
        rerun(a.repo, a.branch)
    if not a.no_fetch:
        new = fetch()
        if new is not None:
            print(f"fetched from {HOST}: {new} new run(s) -> {DEST}\n")
    dirs = repos(a.repo)
    if not dirs:
        print(f"no results in {DEST}" + (f" for '{a.repo}'" if a.repo else ""))
        return 2
    results = show_detail(dirs, a.branch) if a.branch else show_table(dirs, ["develop", "main"])
    if not results:
        return 2
    return 0 if all(r == "passed" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
