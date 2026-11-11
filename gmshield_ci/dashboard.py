"""Read-only terminal dashboard for roberto-server's own screen (tty1).

Shows, per repo and branch, the latest full run (PASSED / FAILED / BLOCKED and the gate that stopped it),
whether a run is in progress, the newest release and the most recent runs. It only reads the files the
pipeline writes (state/, artifacts/); it never takes the poll lock, calls GitHub or changes anything.

  python3 -m gmshield_ci dashboard           # full screen, redraws every few seconds (Ctrl+C to quit)
  python3 -m gmshield_ci dashboard --once    # print one frame and exit (e.g. over SSH)
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import Settings

COLORS = {"green": "32;1", "red": "31;1", "yellow": "33;1", "cyan": "36;1", "dim": "2", "bold": "1"}
RESULT_COLOR = {"passed": "green", "failed": "red", "blocked": "red", "running": "yellow"}


@dataclass
class Running:
    repo: str
    branch: str
    run: str
    started: datetime | None
    last_line: str


@dataclass
class Snapshot:
    latest: dict = field(default_factory=dict)      # (repo, branch) -> history row + "blockers"
    recent: list = field(default_factory=list)      # (repo, branch, row), newest first
    release: tuple | None = None                    # (repo, row) of the newest release
    running: Running | None = None
    poll_active: bool = False                       # someone holds the poll lock right now
    paused: bool = False
    timer: str = "unknown"


# ------------------------------------------------------------------ reading (never writes)

def _rows(path: Path) -> list[dict]:
    rows = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return rows
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue                    # a line being appended right now
        if isinstance(row, dict) and row.get("run") and row.get("result"):
            rows.append(row)
    return rows


def _parse_time(value: str | None) -> datetime | None:
    try:
        t = datetime.fromisoformat(value or "")
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def blockers(run_dir: Path) -> list[str]:
    """'Stage title: first reason' for each stage that failed in a run's summary.json."""
    try:
        data = json.loads((run_dir / "summary.json").read_text())
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for st in data.get("stages", []):
        if st.get("status") == "failed":
            reasons = st.get("reasons") or []
            out.append(f"{st.get('title', st.get('key'))}" + (f": {reasons[0]}" if reasons else ""))
    return out


def lock_held(lock: Path, proc_locks: Path = Path("/proc/locks")) -> bool:
    """True if a process holds the poll lock. Read from /proc/locks so the dashboard never takes it."""
    try:
        st = lock.stat()
        text = proc_locks.read_text()
    except OSError:
        return False
    want = (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)
    for line in text.splitlines():
        parts = line.split()
        # "1: FLOCK  ADVISORY  WRITE 1234 08:02:5678 0 EOF"; waiting requests have "->" after the number
        if len(parts) < 6 or parts[1] != "FLOCK":
            continue
        try:
            major, minor, ino = parts[5].split(":")
            if (int(major, 16), int(minor, 16), int(ino)) == want:
                return True
        except ValueError:
            continue
    return False


def _running(s: Settings) -> Running | None:
    """The newest run folder that has a log but no summary.json yet (only checked while the lock is held)."""
    best = None
    for log in s.artifacts.glob("*/*/*/pipeline.log"):
        run_dir = log.parent
        if (run_dir / "summary.json").exists():
            continue
        try:
            mtime = log.stat().st_mtime
        except OSError:
            continue
        if best is None or mtime > best[0]:
            best = (mtime, run_dir)
    if best is None:
        return None
    run_dir = best[1]
    try:
        lines = [l for l in (run_dir / "pipeline.log").read_text(errors="replace").splitlines() if l.strip()]
    except OSError:
        lines = []
    last = lines[-1] if lines else ""
    if "] " in last:
        last = last.split("] ", 1)[1]
    started = None
    try:
        started = datetime.strptime(run_dir.name[:15], "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    return Running(run_dir.parent.parent.name, run_dir.parent.name, run_dir.name, started, last)


def _timer_state() -> str:
    try:
        out = subprocess.run(["systemctl", "is-active", "gmshield-ci.timer"], capture_output=True,
                             text=True, timeout=5).stdout.strip()
        return out or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def collect(s: Settings, timer: bool = True) -> Snapshot:
    snap = Snapshot()
    for repo in s.repos:
        for branch in s.branches:
            hist = s.artifacts / repo.name / branch / "history.jsonl"
            rows = _rows(hist)
            if not rows:
                continue
            full = [r for r in rows if r.get("mode") == "full"] or rows
            last = dict(full[-1])
            last["blockers"] = blockers(hist.parent / last["run"]) if last["result"] != "passed" else []
            snap.latest[(repo.name, branch)] = last
            snap.recent += [(repo.name, branch, r) for r in rows]
            for r in rows:
                if r.get("release") and (snap.release is None or r.get("started", "") > snap.release[1]["started"]):
                    snap.release = (repo.name, r)
    snap.recent.sort(key=lambda x: x[2].get("started", ""), reverse=True)
    snap.poll_active = lock_held(s.state_dir / "poll.lock")
    snap.running = _running(s) if snap.poll_active else None
    snap.paused = (s.home / "PAUSED").exists()
    snap.timer = _timer_state() if timer else "unknown"
    return snap


# ------------------------------------------------------------------ rendering (pure)

def ago(t: datetime | None, now: datetime) -> str:
    if t is None:
        return "?"
    sec = max(0, int((now - t).total_seconds()))
    if sec < 60:
        return f"{sec}s ago"
    if sec < 3600:
        return f"{sec // 60}m ago"
    if sec < 86400:
        return f"{sec // 3600}h {sec % 3600 // 60:02d}m ago"
    return f"{sec // 86400}d ago"


def when(t: datetime | None, now: datetime) -> str:
    if t is None:
        return "?"
    local, today = t.astimezone(), now.astimezone()
    return f"{local:%H:%M}" if local.date() == today.date() else f"{local:%b %d %H:%M}"


def _dur(sec) -> str:
    sec = int(float(sec or 0))
    return f"{sec // 60}m{sec % 60:02d}s" if sec >= 60 else f"{sec}s"


class Painter:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, text: str, style: str | None) -> str:
        if not self.color or not style:
            return text
        return f"\033[{COLORS[style]}m{text}\033[0m"


def _cell(text: str, width: int) -> str:
    text = str(text)
    return (text[: width - 1] + "…") if len(text) > width else text.ljust(width)


def render(snap: Snapshot, cols: int, rows: int, now: datetime, color: bool = False,
           host: str = "roberto-server", repos: list[str] | None = None,
           branches: tuple[str, ...] = ("develop", "main")) -> list[str]:
    """One frame as a list of lines, each at most `cols` visible characters wide."""
    paint = Painter(color)
    cols = max(cols, 60)
    out: list[tuple[str, str | None]] = []           # (plain text, style) lines

    def line(text: str = "", style: str | None = None) -> None:
        out.append((_cell(text, cols).rstrip(), style))

    title = f" GMshield CI/CD · {host}"
    clock = f"{now.astimezone():%Y-%m-%d %H:%M:%S %Z} "
    line(title + " " * max(1, cols - len(title) - len(clock)) + clock, "bold")
    line("─" * cols, "dim")

    # poller / live status
    if snap.paused:
        line(" Poller: PAUSED (rm ~/gmshield-ci/PAUSED to resume)", "yellow")
    elif snap.timer not in ("active", "unknown"):
        line(f" Poller: timer {snap.timer.upper()}: nothing is being checked", "red")
    if snap.running:
        r = snap.running
        line(f" ▶ RUNNING  {r.repo} {r.branch}  {r.run}  started {ago(r.started, now)}", "yellow")
        if r.last_line:
            line(f"   {r.last_line}", "dim")
    elif snap.poll_active:
        line(" ▶ Polling GitHub…", "yellow")
    else:
        line(" Idle: waiting for pushes to develop or main (checked every minute)", "dim")
    line()

    # latest result per repo and branch
    keys = [(r, b) for r in (repos or sorted({k[0] for k in snap.latest})) for b in branches]
    rw = max([len("Repository")] + [len(k[0]) for k in keys]) + 2
    head = f" {'Repository':<{rw}}{'Branch':<9}{'Result':<10}{'Commit':<10}{'When':<14}"
    line(head + "Commit subject / what blocked it", "bold")
    for repo, branch in keys:
        row = snap.latest.get((repo, branch))
        if not row:
            line(f" {repo:<{rw}}{branch:<9}{'-':<10}not run yet", "dim")
            continue
        result = row["result"]
        started = _parse_time(row.get("started"))
        prefix = f" {repo:<{rw}}{branch:<9}"
        rest = f"{row['sha'][:8]:<10}{when(started, now):<14}"
        warn = int(row.get("warnings") or 0)
        detail = row.get("subject", "")
        if row.get("blockers"):
            detail = "; ".join(row["blockers"])
        elif warn:
            detail = f"{warn} warning{'s' if warn != 1 else ''} · {detail}"
        avail = cols - len(prefix) - 10 - len(rest)
        text = prefix + paint(f"{result.upper():<10}", RESULT_COLOR.get(result)) + rest
        if avail > 3:
            style = "red" if row.get("blockers") else ("yellow" if warn else None)
            text += paint(_cell(detail, avail).rstrip(), style)
        out.append((text, "__raw__"))

    # newest release
    line()
    if snap.release:
        repo, r = snap.release
        line(f" Latest release: {r['release']}  ({repo}, {ago(_parse_time(r.get('started')), now)})", "cyan")
    else:
        line(" Latest release: none yet", "dim")
    line()

    # recent runs, as many as fit above the footer
    line(f" {'When':<14}{'Repository':<{rw}}{'Branch':<9}{'Mode':<7}{'Result':<10}{'Took':<8}{'Commit':<10}Subject",
         "bold")
    room = max(0, rows - len(out) - 2)
    for repo, branch, r in snap.recent[:room]:
        started = _parse_time(r.get("started"))
        prefix = f" {when(started, now):<14}{repo:<{rw}}{branch:<9}{r.get('mode', ''):<7}"
        res = r["result"]
        tail = f"{_dur(r.get('seconds')):<8}{r['sha'][:8]:<10}"
        avail = cols - len(prefix) - 10 - len(tail)
        subj = _cell(r.get("subject", ""), avail).rstrip() if avail > 3 else ""
        out.append((prefix + paint(f"{res.upper():<10}", RESULT_COLOR.get(res)) + tail + subj, "__raw__"))

    while len(out) < rows - 1:
        out.append(("", None))
    footer = " Details and reports: gmshield-results on the workstation"
    updated = f"refreshed {now.astimezone():%H:%M:%S} "
    out = out[: rows - 1]
    out.append((footer + " " * max(1, cols - len(footer) - len(updated)) + updated, "dim"))
    return [text if style == "__raw__" else paint(text, style) for text, style in out]


# ------------------------------------------------------------------ loop

def run(s: Settings, once: bool = False, interval: float = 5.0) -> int:
    host = socket.gethostname()
    repos = [r.name for r in s.repos]
    if once:
        size = shutil.get_terminal_size((120, 40))
        frame = render(collect(s), size.columns, size.lines, datetime.now(timezone.utc), sys.stdout.isatty(),
                       host, repos, s.branches)
        print("\n".join(l.rstrip() for l in frame))
        return 0
    w = sys.stdout.write
    # hide the cursor; on the Linux console also turn off screen blanking and powerdown
    w("\033[?25l" + ("\033[9;0]\033[14;0]" if os.environ.get("TERM") == "linux" else "") + "\033[2J")
    try:
        while True:
            size = shutil.get_terminal_size((80, 24))
            try:
                frame = render(collect(s), size.columns, size.lines, datetime.now(timezone.utc), True,
                               host, repos, s.branches)
            except Exception as e:                       # never die on odd data: show it and keep going
                frame = [f" GMshield CI/CD dashboard: cannot read pipeline data: {e}"]
            w("\033[H" + "\n".join(l + "\033[K" for l in frame) + "\033[J")
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0
    finally:
        w("\033[0m\033[?25h\n")
        sys.stdout.flush()
