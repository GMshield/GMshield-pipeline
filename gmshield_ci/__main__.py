"""gmshield-ci command line (run on roberto-server, in ~/gmshield-ci/runner).

  python3 -m gmshield_ci poll                    # what the systemd timer runs every minute
  python3 -m gmshield_ci run backend develop     # re-run a branch by hand (e.g. after a hotspot review)
  python3 -m gmshield_ci status                  # last result per repo and branch
  python3 -m gmshield_ci dashboard [--once]      # live status screen (runs on tty1, see deploy/)
  python3 -m gmshield_ci selftest                # is the server ready?
  python3 -m gmshield_ci sonar-setup             # one-time SonarQube setup (idempotent)
  python3 -m gmshield_ci sonar-delete KEY        # remove a SonarQube project (tests)
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request

from . import __version__, dashboard, github, pipeline, sonar
from .config import load_settings
from .dockerops import capture


def selftest() -> int:
    s = load_settings()
    checks = []
    rc, out = capture(["docker", "version", "--format", "{{.Server.Version}}"])
    checks.append(("docker daemon", rc == 0, out))
    rc, out = capture(["docker", "buildx", "version"])
    checks.append(("docker buildx", rc == 0, out.split("\n")[0]))
    for name, ref in s.images.items():
        rc, _ = capture(["docker", "image", "inspect", ref])
        checks.append((f"image {name}", rc == 0, ref.split("@")[0]))
    try:
        with urllib.request.urlopen(f"http://{s.registry}/v2/", timeout=5) as r:
            checks.append(("registry", r.status == 200, s.registry))
    except Exception as e:
        checks.append(("registry", False, f"{s.registry}: {e}"))
    rc, _ = capture(["docker", "network", "inspect", s.prod_network])
    checks.append(("prod network", rc == 0, s.prod_network))
    rc, out = capture(["systemctl", "show", s.ci_slice, "-p", "MemoryMax", "--value"])
    checks.append(("ci slice", rc == 0 and out not in ("", "infinity"), f"{s.ci_slice} MemoryMax={out}"))
    checks.append(("sonarqube stack", (sonar.SONAR_DIR / "compose.yaml").is_file(), str(sonar.SONAR_DIR)))
    checks.append(("sonarqube token", bool(sonar._creds().get("SONAR_TOKEN")), str(sonar.CREDS)))
    has_tok = github._token() is not None
    checks.append(("github token", has_tok, str(github.TOKEN_FILE) if has_tok else "missing: no statuses/releases"))
    width = max(len(c[0]) for c in checks)
    for name, ok, info in checks:
        print(f"{'OK  ' if ok else 'FAIL'} {name:<{width}}  {info}")
    return 0 if all(ok for _, ok, _ in checks) else 1


def status() -> int:
    s = load_settings()
    state = json.loads((s.state_dir / "state.json").read_text()) if (s.state_dir / "state.json").exists() else {}
    for repo in s.repos:
        for branch in s.branches:
            st = state.get(repo.name, {}).get(branch)
            print(f"{repo.name:<20} {branch:<8} " + (f"{st['result'].upper():<8} {st['sha'][:8]} {st['run']}"
                                                     if st else "not run yet"))
    return 0


def sonar_setup() -> int:
    try:
        for line in sonar.setup(load_settings().gates):
            print(f"OK  {line}")
        return 0
    except sonar.SonarError as e:
        print(f"FAIL {e}")
        return 1
    finally:
        sonar.Session.close()


def sonar_delete(key: str) -> int:
    try:
        code = sonar.delete_project(key)
        print(f"delete {key}: HTTP {code}")
        return 0 if code in (200, 204, 404) else 1
    finally:
        sonar.Session.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="gmshield-ci", description=f"GMshield CI/CD {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("poll")
    r = sub.add_parser("run")
    r.add_argument("repo", help="GMshield-backend or just backend")
    r.add_argument("branch", choices=["develop", "main"])
    r.add_argument("--sha")
    sub.add_parser("status")
    db = sub.add_parser("dashboard")
    db.add_argument("--once", action="store_true", help="print one frame and exit")
    db.add_argument("--interval", type=float, default=5.0, help="seconds between redraws")
    sub.add_parser("selftest")
    sub.add_parser("sonar-setup")
    d = sub.add_parser("sonar-delete")
    d.add_argument("key")
    a = p.parse_args(argv)
    if a.cmd == "poll":
        return pipeline.poll(load_settings())
    if a.cmd == "run":
        return pipeline.manual_run(load_settings(), a.repo, a.branch, a.sha)
    if a.cmd == "status":
        return status()
    if a.cmd == "dashboard":
        return dashboard.run(load_settings(), once=a.once, interval=max(1.0, a.interval))
    if a.cmd == "sonar-setup":
        return sonar_setup()
    if a.cmd == "sonar-delete":
        return sonar_delete(a.key)
    return selftest()


if __name__ == "__main__":
    sys.exit(main())
