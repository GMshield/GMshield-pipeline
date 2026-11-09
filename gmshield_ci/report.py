"""Reports: summary.json / summary.md per run, history per branch, and an index of everything."""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import Run

LABEL = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP", "pending": "...", "blocked": "BLOCKED"}


def _dur(sec: float) -> str:
    sec = int(sec or 0)
    return f"{sec // 60}m {sec % 60:02d}s" if sec >= 60 else f"{sec}s"


def _links(files: list[str]) -> str:
    return ", ".join(f"[{Path(f).name or f}]({f})" for f in files) or "-"


def write_run(run: "Run") -> None:
    data = {
        "repo": run.repo.name, "branch": run.branch, "run": run.id, "mode": run.mode, "result": run.result,
        "sha": run.sha, "tree": run.tree, "commit": run.commit, "started": run.started.isoformat(),
        "seconds": getattr(run, "seconds", 0), "host": socket.gethostname(),
        "release": run.release_tag, "notes": run.notes, "rolled_back": run.rolled_back,
        "stages": [{k: getattr(r, k) for k in ("key", "title", "gate", "outcome", "status", "threshold",
                                                "reasons", "metrics", "files", "detail", "seconds")}
                   for r in run.records],
    }
    (run.dir / "summary.json").write_text(json.dumps(data, indent=2, default=str))
    (run.dir / "summary.md").write_text(_markdown(run, data))
    branch_dir = run.dir.parent
    with open(branch_dir / "history.jsonl", "a") as fh:
        fh.write(json.dumps({k: data[k] for k in ("run", "mode", "result", "sha", "started", "seconds", "release")}
                            | {"subject": run.commit.get("subject", "")}) + "\n")
    latest = branch_dir / "latest"
    tmp = branch_dir / ".latest.tmp"
    tmp.unlink(missing_ok=True)
    tmp.symlink_to(run.id)
    os.replace(tmp, latest)
    write_index(run.s.artifacts)


def _markdown(run: "Run", d: dict) -> str:
    c = run.commit
    verdict = {"passed": "PASSED", "failed": "FAILED", "blocked": "BLOCKED"}.get(run.result, run.result.upper())
    lines = [f"# {run.repo.name} · {run.branch} · `{run.short}` · {verdict}", "",
             "| | |", "|---|---|",
             f"| Commit | `{run.sha}` {c.get('subject', '')} ({c.get('author', '')}, {c.get('date', '')}) |",
             f"| Run | {run.id} · {run.mode} · {_dur(d['seconds'])} · {d['host']} |"]
    if run.release_tag:
        lines.append(f"| Release | {run.release_tag} |")
    lines += ["", "## Stages", "", "| Stage | Status | Result | Threshold | Time | Reports |",
              "|---|---|---|---|---|---|"]
    for r in run.records:
        lines.append(f"| {r.title} | {LABEL.get(r.status, r.status)} | {r.detail.replace('|', '/')} | "
                     f"{r.threshold} | {_dur(r.seconds)} | {_links(r.files)} |")
    blockers = [(r.title, x) for r in run.records if r.status == "failed" for x in r.reasons]
    if blockers or run.notes:
        lines += ["", "## Outcome", ""]
        lines += [f"- **{t}:** {x}" for t, x in blockers]
        lines += [f"- {n}" for n in run.notes]
    tops = [(r.title, r.metrics.get("top") or r.metrics.get("alerts") or r.metrics.get("where"))
            for r in run.records if r.status != "skipped"]
    tops = [(t, v) for t, v in tops if v]
    if tops:
        lines += ["", "## Top findings", ""]
        seen = set()
        for title, items in tops:
            if title in seen:
                continue
            seen.add(title)
            lines.append(f"**{title}**")
            lines.append("")
            for it in items[:15]:
                if isinstance(it, dict):
                    it = f"{it.get('risk', '').upper()} {it.get('name')} (plugin {it.get('id')}, {it.get('instances')} instance(s))"
                lines.append(f"- {it}")
            lines.append("")
    lines += ["", "Full log: [pipeline.log](pipeline.log) · machine-readable: [summary.json](summary.json)", ""]
    return "\n".join(lines)


def write_index(root: Path) -> None:
    """artifacts/README.md: latest result per repo and branch, plus the 40 most recent runs."""
    latest, recent = [], []
    for hist in sorted(root.glob("*/*/history.jsonl")):
        repo, branch = hist.parent.parent.name, hist.parent.name
        rows = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()]
        if not rows:
            continue
        full = [r for r in rows if r.get("mode") == "full"] or rows
        latest.append((repo, branch, full[-1]))
        recent += [(repo, branch, r) for r in rows]
    recent.sort(key=lambda x: x[2].get("started", ""), reverse=True)
    out = ["# GMshield CI/CD artifacts", "",
           "Produced by the pipeline on roberto-server. Each run folder holds `summary.md`, every scanner "
           "report and SBOM, and `pipeline.log`.", "", "## Latest per branch", "",
           "| Repo | Branch | Result | Commit | When | Run |", "|---|---|---|---|---|---|"]
    for repo, branch, r in latest:
        out.append(f"| {repo} | {branch} | {r['result'].upper()} | `{r['sha'][:8]}` {r.get('subject', '')[:60]} | "
                   f"{r['started'][:16].replace('T', ' ')} | [{r['run']}]({repo}/{branch}/{r['run']}/summary.md) |")
    out += ["", "## Recent runs", "", "| When | Repo | Branch | Mode | Result | Commit | Release |",
            "|---|---|---|---|---|---|---|"]
    for repo, branch, r in recent[:40]:
        out.append(f"| {r['started'][:16].replace('T', ' ')} | {repo} | {branch} | {r.get('mode')} | "
                   f"[{r['result'].upper()}]({repo}/{branch}/{r['run']}/summary.md) | `{r['sha'][:8]}` | "
                   f"{r.get('release') or ''} |")
    (root / "README.md").write_text("\n".join(out) + "\n")
