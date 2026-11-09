"""Optional GitHub reporting: commit statuses and releases.

Active only when a token exists at ~/.config/gmshield/github_token (or GMSHIELD_GITHUB_TOKEN).
Fine-grained token, GMshield repos only: Commit statuses (read/write) and Contents (read/write).
Polling never needs it: the repos are public. Errors here never fail a pipeline run.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

TOKEN_FILE = Path.home() / ".config" / "gmshield" / "github_token"


def _token() -> str | None:
    tok = os.environ.get("GMSHIELD_GITHUB_TOKEN")
    if not tok and TOKEN_FILE.is_file():
        tok = TOKEN_FILE.read_text().strip()
    return tok or None


def _api(method: str, path: str, body: dict) -> tuple[int, dict]:
    tok = _token()
    if not tok:
        return 0, {}
    req = urllib.request.Request(
        f"https://api.github.com{path}", method=method, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {tok}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "gmshield-ci"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return -1, {}


def status(org: str, repo: str, sha: str, state: str, context: str, description: str) -> None:
    _api("POST", f"/repos/{org}/{repo}/statuses/{sha}",
         {"state": state, "context": context, "description": description[:140]})


def create_release(org: str, repo: str, tag: str, sha: str, title: str) -> str:
    if not _token():
        return "skipped (no token)"
    code, _ = _api("POST", f"/repos/{org}/{repo}/releases",
                   {"tag_name": tag, "target_commitish": sha, "name": f"{tag} {title}"[:120],
                    "body": f"Released by the GMshield pipeline on roberto-server.\n\nCommit: {sha}",
                    "make_latest": "true"})
    return "created" if code == 201 else f"failed (HTTP {code})"
