"""Read-only terminal dashboard for roberto-server's own screen (tty1).

The screen is split into a develop section and a main section. Each shows, per repo, the latest full run
(PASSED / FAILED / BLOCKED) with one column per pipeline stage, so the stage that failed stands out, then
what blocked it and the branch's most recent runs. It only reads the files the pipeline writes (state/,
artifacts/); it never takes the poll lock, calls GitHub or changes anything.

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

COLORS = {"green": "32;1", "red": "31;1", "yellow": "33;1", "cyan": "36;1", "dim": "2", "bold": "1",
          "alert": "97;41;1", "head": "30;47;1"}
RESULT_COLOR = {"passed": "green", "failed": "red", "blocked": "red", "running": "yellow"}

# Stage columns per branch, in pipeline order: (summary.json stage key, column label, meaning for the legend)
STAGES = {
    "develop": [("resolve", "Res", "resolve"), ("unit_tests", "Test", "unit tests"),
                ("secrets", "Secr", "Gitleaks"), ("sca_iac:sca", "SCA", "Trivy deps"),
                ("sca_iac:iac", "IaC", "Trivy IaC"), ("sast", "Semg", "Semgrep"),
                ("sonar", "Sonr", "SonarQube"), ("image", "Img", "image"), ("dast", "DAST", "ZAP active")],
    "main": [("resolve", "Res", "resolve"), ("promotion", "Prom", "passed develop"), ("image", "Img", "image"),
             ("publish", "Publ", "registry"), ("deploy", "Depl", "deploy"), ("dast_prod", "DAST", "ZAP passive"),
             ("release", "Rel", "release")],
}
CELL = {"passed": ("ok", "green"), "failed": ("FAIL", "alert"), "skipped": ("skip", "dim")}
NOT_RUN = ("·", "dim")


@dataclass
class Running:
    repo: str
    branch: str
    run: str
    started: datetime | None
    last_line: str


@dataclass
class Snapshot:
    latest: dict = field(default_factory=dict)      # (repo, branch) -> history row + "stages" + "blockers"
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


def stage_results(run_dir: Path) -> tuple[dict[str, str], list[str]]:
    """({stage key: status}, ['Stage title: first reason' for each failed stage]) from a run's summary.json."""
    try:
        data = json.loads((run_dir / "summary.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {}, []
    statuses, failed = {}, []
    for st in data.get("stages", []):
        key, status = str(st.get("key", "")), str(st.get("status", ""))
        statuses[key] = status
        if status == "failed":
            reasons = st.get("reasons") or []
            failed.append(f"{st.get('title', key)}" + (f": {reasons[0]}" if reasons else ""))
    return statuses, failed


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
            last["stages"], last["blockers"] = stage_results(hist.parent / last["run"])
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
# A line is a list of (text, style) segments, so widths can be measured without ANSI codes.

Line = list


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


def _short(repo: str) -> str:
    return repo.removeprefix("GMshield-")


def fit(line: Line, width: int) -> Line:
    """Cut or pad a line to exactly `width` visible characters."""
    out, used = [], 0
    for text, style in line:
        room = width - used
        if room <= 0:
            break
        if len(text) > room:
            text = text[: room - 1] + "…" if room > 1 else text[:room]
        out.append((text, style))
        used += len(text)
    if used < width:
        out.append((" " * (width - used), None))
    return out


def paint(line: Line, color: bool) -> str:
    if not color:
        return "".join(t for t, _ in line)
    return "".join(f"\033[{COLORS[s]}m{t}\033[0m" if s and t.strip() else t for t, s in line)


def _section(branch: str, snap: Snapshot, repos: list[str], width: int, height: int, now: datetime) -> list[Line]:
    stages = STAGES.get(branch) or STAGES["develop"]
    cols = [max(4, len(label)) + 1 for _, label, _ in stages]
    rw = max([len("Repo")] + [len(_short(r)) for r in repos]) + 2
    lines: list[Line] = []

    keys = [(r, branch) for r in repos]
    bad = [k for k in keys if snap.latest.get(k, {}).get("result") not in (None, "passed")]
    title = f" {branch.upper()} "
    summary = (f"{len(bad)} of {len(keys)} not passing" if bad else "all passing") if snap.latest else "no runs yet"
    lines.append([(title, "head"), ("  " + summary, "red" if bad else "green")])

    r = snap.running
    if r and r.branch == branch:
        lines.append([(f" ▶ RUNNING {_short(r.repo)} {r.run.rsplit('-', 1)[-1]} · {ago(r.started, now)} · ", "yellow"),
                      (r.last_line, "dim")])
    else:
        lines.append([(" idle", "dim")])

    head: Line = [(f" {'Repo':<{rw}}{'Result':<9}", "bold")]
    head += [(f"{label:<{w}}", "bold") for (_, label, _), w in zip(stages, cols)]
    head.append(("When", "bold"))
    lines.append(head)
    for repo, _ in keys:
        row = snap.latest.get((repo, branch))
        line: Line = [(f" {_short(repo):<{rw}}", None)]
        running_here = r is not None and r.repo == repo and r.branch == branch
        if not row:
            line.append(("RUNNING  " if running_here else "-        ", "yellow" if running_here else "dim"))
            line += [(f"{NOT_RUN[0]:<{w}}", NOT_RUN[1]) for w in cols]
            line.append(("not run yet", "dim"))
            lines.append(line)
            continue
        res = row["result"]
        line.append((f"{res.upper():<8}", RESULT_COLOR.get(res)))
        line.append((" ", None))
        for (key, _, _), w in zip(stages, cols):
            text, style = CELL.get(row.get("stages", {}).get(key, ""), NOT_RUN)
            line += [(text, style), (" " * (w - len(text)), None)]
        line.append((when(_parse_time(row.get("started")), now), None))
        if running_here:
            line.append((" ▶", "yellow"))
        lines.append(line)

    legend = " "
    for i, (_, label, meaning) in enumerate(stages):
        item = ("" if i == 0 else " · ") + f"{label}={meaning}"
        if len(legend) + len(item) > width and legend.strip():
            lines.append([(legend, "dim")])
            legend, item = " ", item.removeprefix(" · ")
        legend += item
    lines.append([(legend, "dim")])
    lines.append([])

    blocked = [(repo, b) for repo, _ in keys for b in snap.latest.get((repo, branch), {}).get("blockers", [])]
    if blocked:
        lines.append([(" Blocked by", "bold")])
        lines += [[(f" ✗ {_short(repo)}: ", "red"), (b, None)] for repo, b in blocked]
        lines.append([])
    if branch == "main":
        if snap.release:
            repo, rr = snap.release
            lines.append([(f" Latest release: {rr['release']} ({_short(repo)}, "
                           f"{ago(_parse_time(rr.get('started')), now)})", "cyan")])
        else:
            lines.append([(" Latest release: none yet", "dim")])
        lines.append([])

    lines.append([(f" {'When':<13}{'Repo':<{rw}}{'Mode':<6}{'Result':<9}{'Took':<7}{'Commit':<9}Subject", "bold")])
    recent = [(repo, row) for repo, b, row in snap.recent if b == branch]
    for repo, row in recent[: max(0, height - len(lines))]:
        res = row["result"]
        lines.append([(f" {when(_parse_time(row.get('started')), now):<13}{_short(repo):<{rw}}"
                       f"{row.get('mode', ''):<6}", None),
                      (f"{res.upper():<9}", RESULT_COLOR.get(res)),
                      (f"{_dur(row.get('seconds')):<7}{row['sha'][:8]:<9}", None),
                      (row.get("subject", ""), "dim")])
    return [fit(l, width) for l in lines[:height]] + [fit([], width)] * max(0, height - len(lines))


def render(snap: Snapshot, cols: int, rows: int, now: datetime, color: bool = False,
           host: str = "roberto-server", repos: list[str] | None = None,
           branches: tuple[str, ...] = ("develop", "main")) -> list[str]:
    """One frame: header, one section per branch (side by side when wide enough), footer."""
    cols, rows = max(cols, 60), max(rows, 12)
    repos = repos or sorted({k[0] for k in snap.latest})
    top: list[Line] = []
    title = f" GMshield CI/CD · {host}"
    clock = f"{now.astimezone():%Y-%m-%d %H:%M:%S %Z} "
    top.append([(title + " " * max(1, cols - len(title) - len(clock)) + clock, "bold")])
    if snap.paused:
        top.append([(" Poller PAUSED: no pushes are checked (rm ~/gmshield-ci/PAUSED to resume)", "alert")])
    elif snap.timer not in ("active", "unknown"):
        top.append([(f" Poller timer {snap.timer.upper()}: no pushes are checked", "alert")])
    elif snap.poll_active and not snap.running:
        top.append([(" Polling GitHub…", "yellow")])
    top.append([("─" * cols, "dim")])

    footer = " Details and reports: gmshield-results on the workstation"
    updated = f"refreshed {now.astimezone():%H:%M:%S} "
    bottom = [[(footer + " " * max(1, cols - len(footer) - len(updated)) + updated, "dim")]]
    body_h = rows - len(top) - len(bottom)

    side_by_side = len(branches) == 2 and cols >= 150
    body: list[Line] = []
    if side_by_side:
        w = (cols - 3) // 2
        left = _section(branches[0], snap, repos, w, body_h, now)
        right = _section(branches[1], snap, repos, cols - 3 - w, body_h, now)
        body = [l + [(" │ ", "dim")] + r for l, r in zip(left, right)]
    else:
        each = max(1, (body_h - (len(branches) - 1)) // max(1, len(branches)))
        for i, b in enumerate(branches):
            if i:
                body.append([("─" * cols, "dim")])
            body += _section(b, snap, repos, cols, each, now)
        body = body[:body_h] + [[]] * max(0, body_h - len(body))
    frame = [paint(fit(l, cols), color) for l in top + body + bottom]
    return frame if color else [l.rstrip() for l in frame]


# ------------------------------------------------------------------ loop

def run(s: Settings, once: bool = False, interval: float = 5.0) -> int:
    host = socket.gethostname()
    repos = [r.name for r in s.repos]
    if once:
        size = shutil.get_terminal_size((120, 40))
        frame = render(collect(s), size.columns, size.lines, datetime.now(timezone.utc), sys.stdout.isatty(),
                       host, repos, s.branches)
        print("\n".join(frame))
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
