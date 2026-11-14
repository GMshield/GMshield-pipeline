"""Docker: run tool containers with hard time limits, inside the CI cgroup, logging to files."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

UID = f"{os.getuid()}:{os.getgid()}"


def sh(cmd: list[str], log: Path | None = None, timeout: int = 600, env: dict | None = None,
       cwd: Path | None = None) -> int:
    """Run a command; output goes to `log` (appended). Returns exit code, 124 on timeout.

    `env` adds variables to the child's environment (never to the logged command line).
    """
    out = open(log, "ab") if log else subprocess.DEVNULL
    try:
        if log:
            out.write(f"\n$ {' '.join(cmd)}\n".encode())
            out.flush()
        full_env = {**os.environ, **env} if env else None
        return subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, timeout=timeout,
                              env=full_env, cwd=cwd).returncode
    except subprocess.TimeoutExpired:
        if log:
            out.write(f"\n!! timed out after {timeout}s\n".encode())
        return 124
    finally:
        if log:
            out.close()


def capture(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return 124, ""


class Docker:
    def __init__(self, ci_slice: str, run_id: str, instance: str):
        self.ci_slice = ci_slice
        self.run_id = run_id
        self.label = f"gmshield-ci.run={run_id}"
        self.instance_label = f"gmshield-ci.instance={instance}"

    @property
    def labels(self) -> list[str]:
        return ["--label", "gmshield-ci=1", "--label", self.instance_label, "--label", self.label]

    def run(self, name: str, image: str, args: list[str], *, log: Path, timeout: int,
            mounts: list[tuple[Path | str, str, str]] = (), network: str | None = None,
            env: dict | None = None, user: str | None = UID, workdir: str | None = None,
            entrypoint: str | None = None, detach: bool = False, extra: list[str] = (),
            secret_env: dict | None = None) -> int:
        """`secret_env` values reach the container without ever appearing on a command line or in logs."""
        cname = f"gmshield-ci-{self.run_id}-{name}"
        cmd = ["docker", "run", "--name", cname, *self.labels, "--cgroup-parent", self.ci_slice]
        cmd += ["-d"] if detach else ["--rm"]
        for host, cont, mode in mounts:
            cmd += ["-v", f"{host}:{cont}:{mode}"]
        if network:
            cmd += ["--network", network]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        for k in (secret_env or {}):
            cmd += ["-e", k]                       # value passed through the docker CLI's environment
        if user:
            cmd += ["--user", user]
        if workdir:
            cmd += ["-w", workdir]
        if entrypoint is not None:
            cmd += ["--entrypoint", entrypoint]
        cmd += [*extra, image, *args]
        rc = sh(cmd, log, timeout, env=secret_env)
        if rc == 124:
            sh(["docker", "rm", "-f", cname], None, 60)
        return rc

    def cleanup(self) -> None:
        """Remove every container, network, volume and stage image this run created (also after a crash)."""
        cleanup_label(self.label)


def cleanup_label(label: str) -> None:
    _, ids = capture(["docker", "ps", "-aq", "--filter", f"label={label}"])
    if ids:
        sh(["docker", "rm", "-f", "-v", *ids.split()], None, 120)    # -v: their anonymous volumes too
    _, nets = capture(["docker", "network", "ls", "-q", "--filter", f"label={label}"])
    if nets:
        sh(["docker", "network", "rm", *nets.split()], None, 120)
    _, vols = capture(["docker", "volume", "ls", "-q", "--filter", f"label={label}"])
    if vols:
        sh(["docker", "volume", "rm", "-f", *vols.split()], None, 120)    # staging mounts
    _, imgs = capture(["docker", "image", "ls", "-q", "--filter", f"label={label}"])
    if imgs:
        sh(["docker", "image", "rm", "-f", *sorted(set(imgs.split()))], None, 300)  # companion and test stages


def inspect(obj: str, fmt: str) -> str | None:
    rc, out = capture(["docker", "inspect", "--format", fmt, obj])
    return out if rc == 0 and out and out != "<no value>" else None


def container_logs(name: str, dest: Path) -> None:
    with open(dest, "wb") as fh:
        subprocess.run(["docker", "logs", "--timestamps", name], stdout=fh, stderr=subprocess.STDOUT, timeout=60)


def wait_http(url: str, timeout: int) -> bool:
    """Poll a URL from the host until it answers 2xx/3xx."""
    import urllib.request
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status < 400:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def container_healthy(name: str, settle: int = 20) -> bool:
    """For services without HTTP: still running and not restarting after `settle` seconds."""
    time.sleep(settle)
    state = inspect(name, "{{json .State}}")
    if not state:
        return False
    s = json.loads(state)
    return bool(s.get("Running")) and not s.get("Restarting") and int(s.get("ExitCode", 0)) == 0


def prune_images(repo: str, keep: int) -> None:
    """Keep the newest `keep` CI images of a service; old ones only waste disk."""
    rc, out = capture(["docker", "images", repo, "--format", "{{.CreatedAt}}\t{{.Repository}}:{{.Tag}}"])
    if rc != 0 or not out:
        return
    rows = sorted((l.split("\t") for l in out.splitlines() if "\t" in l), reverse=True)
    for _, ref in rows[keep:]:
        sh(["docker", "rmi", ref], None, 120)
