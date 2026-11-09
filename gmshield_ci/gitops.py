"""Git: exact local mirrors of each repo, commit ranges, and clean source exports."""
from __future__ import annotations

import subprocess
import tarfile
from pathlib import Path

from .config import Repo


class GitError(RuntimeError):
    pass


def git(*args: str, timeout: int = 300) -> str:
    try:
        p = subprocess.run(["git", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {' '.join(args[:3])} timed out") from e
    if p.returncode != 0:
        raise GitError(f"git {' '.join(args[:4])}: {p.stderr.strip()[:300]}")
    return p.stdout.strip()


def sync_mirror(repo: Repo, mirrors: Path) -> Path:
    """Bare mirror whose local branches and tags always equal the remote's (forced, pruned)."""
    path = mirrors / f"{repo.name}.git"
    if not (path / "HEAD").exists():
        path.mkdir(parents=True, exist_ok=True)
        git("init", "--bare", "--quiet", str(path))
        git("-C", str(path), "remote", "add", "origin", repo.url)
        git("-C", str(path), "config", "--replace-all", "remote.origin.fetch", "+refs/heads/*:refs/heads/*")
        git("-C", str(path), "config", "--add", "remote.origin.fetch", "+refs/tags/*:refs/tags/*")
    else:
        git("-C", str(path), "remote", "set-url", "origin", repo.url)
    git("-C", str(path), "fetch", "--prune", "--prune-tags", "--quiet", "origin", timeout=900)
    return path


def head(mirror: Path, branch: str) -> str | None:
    try:
        return git("-C", str(mirror), "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}")
    except GitError:
        return None


def tree(mirror: Path, sha: str) -> str:
    return git("-C", str(mirror), "rev-parse", f"{sha}^{{tree}}")


def is_ancestor(mirror: Path, old: str, new: str) -> bool:
    p = subprocess.run(["git", "-C", str(mirror), "merge-base", "--is-ancestor", old, new],
                       capture_output=True, timeout=120)
    return p.returncode == 0


def new_commits(mirror: Path, old: str | None, new: str) -> list[str]:
    """Commits introduced by a push, oldest first. Unknown or rewritten history: just the head."""
    if old and old != new and is_ancestor(mirror, old, new):
        out = git("-C", str(mirror), "rev-list", "--reverse", f"{old}..{new}")
        return [s for s in out.splitlines() if s] or [new]
    return [new]


def commit_info(mirror: Path, sha: str) -> dict:
    out = git("-C", str(mirror), "log", "-1", "--format=%H%x00%an%x00%aI%x00%s", sha)
    full, author, date, subject = (out.split("\x00") + ["", "", "", ""])[:4]
    return {"sha": full, "author": author, "date": date, "subject": subject}


def export(mirror: Path, sha: str, dest: Path) -> None:
    """Plain copy of the commit's files (no .git), so scanners and builds see exactly that commit."""
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(["git", "-C", str(mirror), "archive", "--format=tar", sha],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    # Reviewed: the archive comes from `git archive` (git trees cannot hold ".." or absolute
    # paths) and filter="data" rejects traversal, links outside dest and device files.
    with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:  # nosemgrep: trailofbits.python.tarfile-extractall-traversal.tarfile-extractall-traversal
        tar.extractall(dest, filter="data")
    if proc.wait(timeout=300) != 0:
        raise GitError(f"git archive {sha[:12]} failed: {proc.stderr.read().decode()[:300] if proc.stderr else ''}")
