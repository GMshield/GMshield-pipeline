"""Housekeeping: keeps Docker and old run folders from filling roberto-server's disk.

The poller calls `maybe_run` at the end of every poll, while it still holds the poll lock, so housekeeping
never overlaps a pipeline run. It runs once a day inside a quiet window (default 03:00-06:00
America/Sao_Paulo), or at the next idle poll when free disk drops below `min_free_percent`.
By hand: `python3 -m gmshield_ci clean --dry-run` shows what would go, `clean` does it.

Removed, and what is always kept ([housekeeping] in tools.toml):
- Docker build cache above `build_cache_max_gb`. BuildKit drops the least recently used records
  first, so the layers recent builds use stay and builds keep their speed.
- Production tags `<registry>/gmshield-<service>:<sha>`: keeps `:prod`, every image a container uses
  (the running service and its `-previous` rollback copy) and the newest `keep_registry_tags`.
- CI images `gmshield-ci/<service>:<sha>`: keeps the newest `keep_images_per_service`; a service with
  no new image for `inactive_service_days` loses all of them.
- Any other Docker image no container uses that was created more than `image_max_age_days` ago,
  except the pinned images (tools.toml [images], infra/ and sonarqube/ compose files).
- Dangling images and unused anonymous volumes.
- Run folders `artifacts/<repo>/<branch>/<run-id>/` older than `run_max_age_days`. Always kept: the
  newest `keep_runs_per_branch`, `latest`, the run recorded in state.json, every run a release links
  to, and `history.jsonl` (one line per run, so the record of old runs survives).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import RUNNER_DIR, Settings, read_toml
from .dockerops import capture, sh

RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{8}$")
DEFAULTS = {
    "timezone": "America/Sao_Paulo",
    "quiet_hours": [3, 6],            # local [start, end) hour
    "min_free_percent": 15,           # below this, run at the next idle poll (at most once an hour)
    "build_cache_max_gb": 40,
    "keep_registry_tags": 3,
    "inactive_service_days": 30,
    "image_max_age_days": 90,
    "run_max_age_days": 30,
    "keep_runs_per_branch": 20,
}
DAILY_GAP = timedelta(hours=20)
LOW_DISK_GAP = timedelta(hours=1)


def opt(s: Settings, key: str):
    return s.housekeeping.get(key, DEFAULTS[key])


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S}Z housekeeping: {msg}", flush=True)


# ------------------------------------------------------------------ decisions (pure, unit-tested)

def due(s: Settings, now: datetime, last: datetime | None, free_percent: float) -> str | None:
    """Why housekeeping should run now, or None."""
    if free_percent < opt(s, "min_free_percent"):
        if last is None or now - last >= LOW_DISK_GAP:
            return f"low disk ({free_percent:.0f}% free)"
        return None
    start, end = opt(s, "quiet_hours")
    if start <= now.astimezone(ZoneInfo(opt(s, "timezone"))).hour < end and (last is None or now - last >= DAILY_GAP):
        return "daily"
    return None


def run_started(name: str) -> datetime:
    return datetime.strptime(name[:15], "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)


def runs_to_delete(branch_dir: Path, now: datetime, max_age_days: int, keep_newest: int,
                   protected: set[str]) -> list[Path]:
    runs = sorted(p for p in branch_dir.iterdir() if RUN_ID.match(p.name) and p.is_dir() and not p.is_symlink())
    keep = {p.name for p in runs[-keep_newest:]} if keep_newest > 0 else set()
    latest = branch_dir / "latest"
    if latest.is_symlink():
        keep.add(Path(os.readlink(latest)).name)
    return [p for p in runs if p.name not in keep and p.name not in protected
            and now - run_started(p.name) > timedelta(days=max_age_days)]


def protected_runs(artifacts: Path, state: dict) -> set[str]:
    """Runs a release links to, and the last run of every repo and branch in state.json."""
    keep = {Path(os.readlink(link)).name for link in artifacts.glob("*/releases/*/run") if link.is_symlink()}
    keep |= {b.get("run", "") for branches in state.values() for b in branches.values()}
    return keep


@dataclass(frozen=True)
class Image:
    id: str
    repo: str
    tag: str
    created: datetime

    @property
    def ref(self) -> str:
        return self.id if self.tag == "<none>" else f"{self.repo}:{self.tag}"


def images_to_remove(s: Settings, images: list[Image], protected_ids: set[str],
                     now: datetime) -> list[tuple[str, str]]:
    """(ref, reason) for every image tag housekeeping removes."""
    out: list[tuple[str, str]] = []
    groups: dict[str, list[Image]] = {}
    for im in images:
        if im.id in protected_ids:
            continue
        if im.repo.startswith(f"{s.registry}/gmshield-") or im.repo.startswith("gmshield-ci/"):
            groups.setdefault(im.repo, []).append(im)
        elif now - im.created > timedelta(days=opt(s, "image_max_age_days")):
            out.append((im.ref, f"unused, created {im.created:%Y-%m-%d}"))
    for repo, ims in groups.items():
        ims.sort(key=lambda i: i.created, reverse=True)
        if repo.startswith("gmshield-ci/"):
            if now - ims[0].created > timedelta(days=opt(s, "inactive_service_days")):
                out += [(i.ref, "service inactive") for i in ims]
            else:
                out += [(i.ref, "older CI image") for i in ims[s.limit("keep_images_per_service", 3):]]
        else:
            tags = [i for i in ims if i.tag != "prod"]
            out += [(i.ref, "older production tag") for i in tags[opt(s, "keep_registry_tags"):]]
    return out


# ------------------------------------------------------------------ Docker and disk facts

def list_images() -> list[Image]:
    rc, out = capture(["docker", "image", "ls", "--no-trunc", "--format", "{{json .}}"])
    if rc != 0:
        raise RuntimeError("docker image ls failed")
    images = []
    for line in out.splitlines():
        d = json.loads(line)
        created = datetime.strptime(d["CreatedAt"][:25], "%Y-%m-%d %H:%M:%S %z")
        images.append(Image(d["ID"], d["Repository"], d["Tag"], created))
    return images


def pinned_refs() -> list[str]:
    refs = list(read_toml(RUNNER_DIR / "tools.toml").get("images", {}).values())
    for compose in (RUNNER_DIR / "infra" / "compose.yaml", RUNNER_DIR / "sonarqube" / "compose.yaml"):
        if compose.is_file():
            refs += re.findall(r"^\s*image:\s*(\S+)", compose.read_text(), re.M)
    return refs


def protected_image_ids() -> set[str]:
    """Images any container uses (running or stopped, so rollback copies stay) and every pinned image."""
    ids: set[str] = set()
    rc, cids = capture(["docker", "ps", "-aq"])
    if rc != 0:
        raise RuntimeError("docker ps failed")
    if cids:
        rc, out = capture(["docker", "inspect", "--format", "{{.Image}}", *cids.split()])
        if rc != 0:
            raise RuntimeError("docker inspect failed")
        ids |= set(out.split())
    for ref in pinned_refs():
        rc, out = capture(["docker", "image", "inspect", "--format", "{{.Id}}", ref])
        if rc == 0 and out:
            ids.add(out)
    return ids


def free_percent(path: str) -> float:
    st = os.statvfs(path)
    return 100.0 * st.f_bavail / st.f_blocks


def disk_free(s: Settings) -> float:
    _, root = capture(["docker", "info", "--format", "{{.DockerRootDir}}"])
    paths = [p for p in (root or "/var/lib/docker", str(s.home)) if Path(p).exists()]
    return min(free_percent(p) for p in paths) if paths else 100.0


def build_cache_bytes() -> int:
    rc, out = capture(["docker", "system", "df", "--format", "{{json .}}"])
    for line in out.splitlines() if rc == 0 else []:
        d = json.loads(line)
        if d.get("Type") == "Build Cache":
            m = re.match(r"([\d.]+)\s*([kMGT]?B)", d.get("Size", ""))
            if m:
                return int(float(m[1]) * {"B": 1, "kB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m[2]])
    return 0


# ------------------------------------------------------------------ the job

def journal(s: Settings) -> Path:
    return s.state_dir / "housekeeping.jsonl"


def last_run(s: Settings) -> datetime | None:
    try:
        lines = journal(s).read_text().splitlines()
        return datetime.fromisoformat(json.loads(lines[-1])["at"]) if lines else None
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError):
        return None


def run(s: Settings, reason: str = "manual", dry_run: bool = False) -> dict:
    now = datetime.now(timezone.utc)
    report = {"at": now.isoformat(), "reason": reason, "dry_run": dry_run, "free_percent_before": round(disk_free(s), 1)}

    # 1. run folders
    try:
        state = json.loads((s.state_dir / "state.json").read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        state = {}
    keep = protected_runs(s.artifacts, state)
    old_runs = []
    for branch_dir in sorted(p for p in s.artifacts.glob("*/*") if p.is_dir() and p.name != "releases"):
        old_runs += runs_to_delete(branch_dir, now, opt(s, "run_max_age_days"), opt(s, "keep_runs_per_branch"), keep)
    report["runs_removed"] = [str(p.relative_to(s.artifacts)) for p in old_runs]
    if not dry_run:
        for p in old_runs:
            shutil.rmtree(p, ignore_errors=True)

    # 2. Docker images (before the cache, so the cache their layers held becomes prunable)
    victims = images_to_remove(s, list_images(), protected_image_ids(), now)
    report["images_removed"] = [f"{ref} ({why})" for ref, why in victims]
    if not dry_run:
        failed = [ref for ref, _ in victims if sh(["docker", "rmi", ref], None, 300) != 0]
        report["images_kept_on_error"] = failed           # e.g. a container started using it meanwhile
        sh(["docker", "image", "prune", "-f"], None, 600)        # dangling only
        sh(["docker", "volume", "prune", "-f"], None, 600)       # anonymous volumes no container uses

    # 3. build cache
    cap = f"{opt(s, 'build_cache_max_gb')}GB"
    report["build_cache_gb_before"] = round(build_cache_bytes() / 1e9, 1)
    if not dry_run:
        sh(["docker", "builder", "prune", "-f", "--max-used-space", cap], None, 1800)
        report["build_cache_gb_after"] = round(build_cache_bytes() / 1e9, 1)
    report["build_cache_cap"] = cap
    report["free_percent_after"] = round(disk_free(s), 1)
    if not dry_run:
        s.state_dir.mkdir(parents=True, exist_ok=True)
        with open(journal(s), "a") as fh:
            fh.write(json.dumps(report) + "\n")
    return report


def maybe_run(s: Settings) -> None:
    """Called by the poller with the poll lock held. Never raises: housekeeping must not break CI."""
    try:
        reason = due(s, datetime.now(timezone.utc), last_run(s), disk_free(s))
        if not reason:
            return
        log(f"starting ({reason})")
        r = run(s, reason)
        log(f"done: {len(r['runs_removed'])} run folder(s), {len(r['images_removed'])} image tag(s), build cache "
            f"{r['build_cache_gb_before']} -> {r.get('build_cache_gb_after')} GB, free disk "
            f"{r['free_percent_before']}% -> {r['free_percent_after']}%")
    except Exception:
        log("failed:\n" + traceback.format_exc())
        try:                                   # recorded as a run, so a failure is not retried every minute
            s.state_dir.mkdir(parents=True, exist_ok=True)
            with open(journal(s), "a") as fh:
                fh.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "error": traceback.format_exc(limit=3)}) + "\n")
        except OSError:
            pass
