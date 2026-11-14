"""Pipeline stages. Each returns (outcome, metrics, files, detail); outcome is ok | error | skipped."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from . import gates
from .config import Contract, container_args
from .dockerops import UID, capture, container_healthy, container_logs, inspect, sh

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import Run

GIT_SAFE = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}


@dataclass
class Record:
    key: str
    title: str
    gate: str | None
    outcome: str = "ok"
    status: str = "pending"          # passed | failed | skipped
    threshold: str = "-"
    reasons: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    detail: str = ""
    seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)   # shown in every report; never change the status


def execute(run: "Run", key: str, title: str, gate: str | list[str] | None, fn, *args) -> list[Record]:
    """Time a stage, never let it crash the pipeline, and judge it against its gate(s)."""
    run.log(f"stage start: {title}")
    t0 = time.monotonic()
    try:
        outcome, metrics, files, detail = fn(run, *args)
    except Exception as e:  # a crashed stage is an error, judged fail-closed
        outcome, metrics, files, detail = "error", {"error": f"{type(e).__name__}: {e}"}, [], f"crashed: {e}"
    seconds = round(time.monotonic() - t0, 1)
    recs = []
    for g in (gate if isinstance(gate, list) else [gate]):
        r = Record(key if not isinstance(gate, list) else f"{key}:{g}",
                   title if not isinstance(gate, list) else run.titles.get(g, title), g,
                   outcome=outcome, metrics=metrics, files=files,
                   detail=metrics.get("details", {}).get(g, detail), seconds=seconds,
                   warnings=list(metrics.get("warnings") or []))
        if g:
            r.status, r.threshold, r.reasons = gates.judge(g, outcome, metrics, run.s.gates)
        else:
            r.status = {"ok": "passed", "skipped": "skipped"}.get(outcome, "failed")
            if outcome == "error":
                r.reasons = [metrics.get("error", detail or "error")]
        run.log(f"stage end: {r.title}: {r.status} ({seconds}s) {'; '.join(r.reasons)}")
        for w in r.warnings:
            run.log(f"stage warning: {r.title}: {w}")
        recs.append(r)
    with run.lock:
        run.records.extend(recs)
    return recs


def _skip(why: str):
    return "skipped", {}, [], why


def _error(why: str, files=()):
    return "error", {"error": why}, list(files), why


# ------------------------------------------------------------------ source stages

def secrets(run: "Run"):
    out = run.dir / "gitleaks.json"
    rc = run.docker.run(
        "gitleaks", run.s.images["gitleaks"],
        ["git", "/repo", "--log-opts", run.log_opts, "-f", "json", "-r", "/out/gitleaks.json",
         "--exit-code", "0", "--redact", "--no-banner", "-l", "warn", "--max-target-megabytes", "10",
         "-i", "/src"],
        log=run.dir / "gitleaks.log", timeout=run.s.limit("gitleaks", 600),
        mounts=[(run.mirror, "/repo", "ro"), (run.src, "/src", "ro"), (run.dir, "/out", "rw")],
        env=GIT_SAFE, network="none")
    if rc != 0 or not out.exists():
        return _error(f"gitleaks exit {rc}", ["gitleaks.log"])
    m = gates.parse_gitleaks(out)
    scope = {run.sha: "full history", f"{run.sha}^!": "this commit"}.get(
        run.log_opts, f"{len(run.push)} pushed commit(s)")
    m["scope"] = scope
    return "ok", m, ["gitleaks.json", "gitleaks.log"], f"{m['findings']} finding(s), {scope}"


CONTAINER_HOME = "/home/ci"


def private_home(run: "Run", tool: str) -> tuple[Path, str, str]:
    """A per-run, owner-only home folder for a tool container (instead of a shared /tmp)."""
    d = run.work / "home" / tool
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d, CONTAINER_HOME, "rw"


def sast(run: "Run"):
    args = ["semgrep", "scan"]
    for rs in run.s.semgrep_rulesets:
        args += ["--config", rs]
    args += ["--metrics=off", "--disable-version-check", "--json-output=/out/semgrep.json",
             "--sarif-output=/out/semgrep.sarif", "--timeout=30", "--jobs=2", "--max-memory=1500", "/src"]
    rc = run.docker.run("semgrep", run.s.images["semgrep"], args, log=run.dir / "semgrep.log",
                        timeout=run.s.limit("semgrep", 1200),
                        mounts=[(run.src, "/src", "ro"), (run.dir, "/out", "rw"), private_home(run, "semgrep")],
                        env={"HOME": CONTAINER_HOME, "SEMGREP_SEND_METRICS": "off"}, workdir="/src")
    out = run.dir / "semgrep.json"
    if rc not in (0, 1) or not out.exists():
        return _error(f"semgrep exit {rc}", ["semgrep.log"])
    m = gates.parse_semgrep(out)
    warned = f"; WARNING: {m['unscanned_files']} file(s) not fully scanned" if m["warnings"] else ""
    return "ok", m, ["semgrep.json", "semgrep.sarif", "semgrep.log"], \
        f"high {m['high']}, medium {m['medium']}, low {m['low']}{warned}"


def _trivy(run: "Run", name: str, args: list[str], extra_mounts=()) -> int:
    run.s.cache.joinpath("trivy").mkdir(parents=True, exist_ok=True)
    return run.docker.run(
        name, run.s.images["trivy"],
        [args[0], "--cache-dir", "/cache", "--skip-version-check", "--no-progress", "--timeout", "15m", *args[1:]],
        log=run.dir / "trivy.log", timeout=run.s.limit("trivy", 1200),
        mounts=[(run.dir, "/out", "rw"), (run.s.cache / "trivy", "/cache", "rw"), private_home(run, "trivy"),
                *extra_mounts],
        env={"HOME": CONTAINER_HOME}, workdir="/src" if args[0] == "fs" else None)


def sca_iac(run: "Run"):
    src = [(run.src, "/src", "ro")]
    rc = _trivy(run, "trivy-fs", ["fs", "--scanners", "vuln,misconfig", "--format", "json",
                                  "--output", "/out/trivy-fs.json", "/src"], src)
    out = run.dir / "trivy-fs.json"
    if rc != 0 or not out.exists():
        return _error(f"trivy fs exit {rc}", ["trivy.log"])
    _trivy(run, "trivy-sbom", ["fs", "--scanners", "vuln", "--format", "cyclonedx",
                               "--output", "/out/sbom-source.cdx.json", "/src"], src)
    m = gates.parse_trivy(out)
    files = ["trivy-fs.json", "trivy.log"] + (["sbom-source.cdx.json"] if (run.dir / "sbom-source.cdx.json").exists() else [])
    m["details"] = {
        "sca": (f"dependency vulns C{m['vuln']['CRITICAL']}/H{m['vuln']['HIGH']} "
                f"(fixable C{m['vuln_fixable']['CRITICAL']}/H{m['vuln_fixable']['HIGH']})"),
        "iac": f"misconfigurations C{m['misconfig']['CRITICAL']}/H{m['misconfig']['HIGH']}",
    }
    return "ok", m, files, "; ".join(m["details"].values())


def _buildx(run: "Run", log: Path, *args: str, timeout: int) -> int:
    c = run.contract
    return sh(["docker", "buildx", "build", "--progress=plain", "--cgroup-parent", run.s.ci_slice,
               "-f", str(run.src / c.context / c.dockerfile), "--build-arg", f"GIT_SHA={run.sha}",
               *args, str(run.src / c.context)], log, timeout)


def unit_tests(run: "Run"):
    c = run.contract
    if not c.has_dockerfile:
        return _skip("no Dockerfile yet")
    if c.test_target.lower() not in c.dockerfile_stages:
        return _skip(f"Dockerfile has no '{c.test_target}' stage")
    log = run.dir / "unit-tests.log"
    rc = _buildx(run, log, "--target", c.test_target, timeout=run.s.limit("unit_tests", 1800))
    if rc == 124:
        return _error("unit tests timed out", ["unit-tests.log"])
    files = ["unit-tests.log"]
    if "test-reports" in c.dockerfile_stages:
        _buildx(run, log, "--target", "test-reports", "--output", f"type=local,dest={run.dir / 'unit-tests'}",
                timeout=600)
        files.append("unit-tests/")
    return "ok", {"exit_code": rc}, files, "passed" if rc == 0 else f"failed (exit {rc})"


# ------------------------------------------------------------------ image

def image(run: "Run"):
    c = run.contract
    if not c.has_dockerfile:
        return _skip("no Dockerfile yet")
    log = run.dir / "image-build.log"
    rc = _buildx(run, log, "-t", run.local_image, "--load",
                 "--label", f"org.opencontainers.image.revision={run.sha}",
                 "--label", f"org.opencontainers.image.source={run.repo.url}",
                 timeout=run.s.limit("build", 1800))
    if rc != 0:
        return "ok", {"build_exit": rc, **_empty_trivy()}, ["image-build.log"], f"build failed (exit {rc})"
    run.image_built = True
    tar = run.work / "image.tar"
    if sh(["docker", "save", "-o", str(tar), run.local_image], log, 900) != 0:
        return _error("docker save failed", ["image-build.log"])
    try:
        mounts = [(run.work, "/in", "ro")]
        rc = _trivy(run, "trivy-image", ["image", "--input", "/in/image.tar", "--scanners", "vuln",
                                         "--format", "json", "--output", "/out/trivy-image.json"], mounts)
        out = run.dir / "trivy-image.json"
        if rc != 0 or not out.exists():
            return _error(f"trivy image exit {rc}", ["image-build.log", "trivy.log"])
        _trivy(run, "trivy-image-sbom", ["image", "--input", "/in/image.tar", "--format", "cyclonedx",
                                         "--output", "/out/sbom-image.cdx.json"], mounts)
    finally:
        tar.unlink(missing_ok=True)
    m = {"build_exit": 0, **gates.parse_trivy(out),
         "image": run.local_image, "size": inspect(run.local_image, "{{.Size}}")}
    files = ["image-build.log", "trivy-image.json"] + (["sbom-image.cdx.json"] if (run.dir / "sbom-image.cdx.json").exists() else [])
    return "ok", m, files, f"vulns C{m['vuln']['CRITICAL']}/H{m['vuln']['HIGH']} (fixable C{m['vuln_fixable']['CRITICAL']}/H{m['vuln_fixable']['HIGH']})"


def _empty_trivy() -> dict:
    zero = {s: 0 for s in gates.SEVERITIES}
    return {"vuln": dict(zero), "vuln_fixable": dict(zero), "misconfig": dict(zero), "top": []}


# ------------------------------------------------------------------ DAST

def _probe(run: "Run", network: str, url: str, log: Path, ca_cert: Path | None = None) -> bool:
    """Wait for the app from inside its Docker network (works for internal networks too).

    With `ca_cert` (HTTPS), only that CA certificate is mounted and curl verifies the app against it.
    """
    tries = max(1, run.s.limit("startup", 180) // 3)
    cacert = "--cacert /certs/ca.crt " if ca_cert else ""
    rc = run.docker.run("probe", run.s.images["zap"],
                        ["sh", "-c", f"for i in $(seq 1 {tries}); do curl -fsS {cacert}-o /dev/null '{url}' && exit 0; "
                                     f"sleep 3; done; exit 1"],
                        log=log, timeout=run.s.limit("startup", 180) + 60, network=network, user=None,
                        entrypoint="", mounts=[(ca_cert, "/certs/ca.crt", "ro")] if ca_cert else [])
    return rc == 0


def _zap_ignore(run: "Run") -> set[str]:
    f = run.src / ".gmshield" / "zap-ignore.txt"
    if not f.is_file():
        return set()
    return {l.split("#")[0].strip() for l in f.read_text().splitlines() if l.split("#")[0].strip()}


def _zap(run: "Run", network: str, base: str, outdir: Path, active: bool):
    c, lim = run.contract, run.s.limits
    outdir.mkdir(parents=True, exist_ok=True)
    spider = str(lim.get("zap_spider_minutes", 2))
    if active and c.openapi:
        script, extra = "zap-api-scan.py", ["-t", base + c.openapi, "-f", "openapi"]
    elif active:
        script, extra = "zap-full-scan.py", ["-t", base + c.dast_path, "-m", spider]
    else:
        script, extra = "zap-baseline.py", ["-t", base + c.dast_path, "-m", spider]
    zopts = "-silent"
    if active:
        zopts += f" -config scanner.maxScanDurationInMins={lim.get('zap_active_minutes', 10)} -config scanner.threadPerHost=2"
    rc = run.docker.run("zap", run.s.images["zap"],
                        [script, *extra, "-I", "-T", "10", "-J", "zap.json", "-r", "zap.html", "-w", "zap.md",
                         "-x", "zap.xml", "-z", zopts],
                        log=outdir / "zap.log",
                        timeout=run.s.limit("zap_active" if active else "zap_passive", 1800),
                        mounts=[(outdir, "/zap/wrk", "rw")], network=network, user=None)
    rel = outdir.name
    files = [f"{rel}/{f}" for f in ("zap.html", "zap.json", "zap.md", "zap.xml", "zap.log") if (outdir / f).exists()]
    if rc in (3, 124) or not (outdir / "zap.json").exists():
        return _error(f"ZAP {script} exit {rc}", files)
    m = gates.parse_zap(outdir / "zap.json", _zap_ignore(run))
    m["scan"] = script.removesuffix(".py")
    return "ok", m, files, f"{m['scan']}: high {m['high']}, medium {m['medium']}, low {m['low']}"


# ------------------------------------------------------------------ throwaway services and staging

# Fixed test-mode credentials: they must match GMshield-backend's application-test-mode.yaml.
SERVICE_SPECS = {
    "postgres": {"env": {"POSTGRES_DB": "gmshield", "POSTGRES_USER": "gmshield",
                         "POSTGRES_PASSWORD": "gmshield-test-mode"},
                 "args": [], "tmpfs": "/var/lib/postgresql",
                 # over TCP: the image's temporary init server listens on the socket only
                 "ready": ["pg_isready", "-h", "127.0.0.1", "-U", "gmshield", "-d", "gmshield"], "expect": ""},
    "redis": {"env": {}, "args": ["redis-server", "--save", "", "--appendonly", "no"], "tmpfs": "/data",
              "ready": ["redis-cli", "ping"], "expect": "PONG"},
}


def _cname(run: "Run", name: str) -> str:
    return f"gmshield-ci-{run.id}-{name}"


def _network(run: "Run", name: str, log: Path) -> bool:
    return sh(["docker", "network", "create", "--internal", *run.docker.labels, name], log, 60) == 0


def _remove(*names: str) -> None:
    """Remove containers with their anonymous volumes."""
    if names:
        sh(["docker", "rm", "-f", "-v", *names], None, 120)


def start_services(run: "Run", network: str, names: list[str], prefix: str, outdir: Path,
                   log: Path) -> tuple[list[str], str | None]:
    """Start throwaway services on `network` under their own names and wait until each is ready.

    Returns (container names, error); on error each service's log is kept in `outdir`.
    """
    started: list[str] = []
    for svc in names:
        spec = SERVICE_SPECS[svc]
        rc = run.docker.run(f"{prefix}-{svc}", run.s.images[svc], spec["args"], log=log, timeout=300,
                            network=network, env=spec["env"], user=None, detach=True,
                            extra=["--network-alias", svc, "--tmpfs", spec["tmpfs"]])
        started.append(_cname(run, f"{prefix}-{svc}"))
        if rc != 0:
            return started, f"{svc} failed to start"
    limit = run.s.limit("startup", 180)
    deadline = time.monotonic() + limit
    pending = dict(zip(names, started))
    while pending and time.monotonic() < deadline:
        for svc, cname in list(pending.items()):
            rc, out = capture(["docker", "exec", cname, *SERVICE_SPECS[svc]["ready"]], timeout=30)
            if rc == 0 and SERVICE_SPECS[svc]["expect"] in out:
                pending.pop(svc)
        if pending:
            time.sleep(2)
    if pending:
        for svc, cname in pending.items():
            container_logs(cname, outdir / f"{svc}.log")
        return started, f"{', '.join(pending)} not ready within {limit}s"
    return started, None


def _service_logs(names: list[str], containers: list[str], outdir: Path) -> list[str]:
    for svc, cname in zip(names, containers):
        try:
            container_logs(cname, outdir / f"{svc}.log")
        except Exception:
            pass
    return [f"{outdir.name}/{svc}.log" for svc in names if (outdir / f"{svc}.log").exists()]


def staging_certs(run: "Run", aliases: list[str]) -> Path | None:
    """A throwaway CA and a leaf certificate for the app, made on the host with openssl for this run only.

    The CA key never leaves the run's work folder; the returned folder holds ca.crt, tls.crt, tls.key.
    The private authority of production (Story 1.6) never enters the CI slice.
    """
    base = run.work / "staging-ca"
    out = run.work / "staging-certs"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    out.mkdir(parents=True, exist_ok=True)
    log = run.dir / "dast" / "staging.log"
    ext = base / "leaf.ext"
    ext.write_text(f"subjectAltName={','.join(f'DNS:{a}' for a in aliases)}\nbasicConstraints=CA:FALSE\n"
                   "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc"]
    steps = [
        ["openssl", "req", "-x509", *ec, "-keyout", str(base / "ca.key"), "-out", str(out / "ca.crt"),
         "-days", "2", "-subj", f"/CN=GMshield CI throwaway CA {run.id}",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        ["openssl", "req", *ec, "-keyout", str(out / "tls.key"), "-out", str(base / "tls.csr"),
         "-subj", f"/CN={aliases[0]}"],
        ["openssl", "x509", "-req", "-in", str(base / "tls.csr"), "-CA", str(out / "ca.crt"),
         "-CAkey", str(base / "ca.key"), "-CAserial", str(base / "ca.srl"), "-CAcreateserial",
         "-out", str(out / "tls.crt"), "-days", "2", "-extfile", str(ext)],
    ]
    for cmd in steps:
        if sh(cmd, log, 60) != 0:
            return None
    # The app runs under its own user: the throwaway files must be readable by it.
    out.chmod(0o755)
    for f in out.iterdir():
        f.chmod(0o644)
    return out


def _mount_dirs(c: Contract, root: Path) -> Path:
    for m in c.mounts:
        d = root / m.name
        if not d.exists():
            d.mkdir(parents=True, mode=0o700)
            os.chmod(d, 0o700)
    return root


def dast_staging(run: "Run"):
    """develop: run the new image in an isolated, internet-less network and attack it (active scan).

    The app runs with GMSHIELD_MODE=test, beside its throwaway services and companions, with the same
    caps and hardening as production but inside the CI slice.
    """
    c = run.contract
    if not c.http:
        return _skip("no HTTP port declared (.gmshield/pipeline.toml [service].port)")
    if not run.image_built:
        return _skip("no image to test")
    outdir = run.dir / "dast"
    outdir.mkdir(parents=True, exist_ok=True)
    log = outdir / "staging.log"
    net = f"gmshield-ci-{run.id}"
    app = _cname(run, "app")
    containers: list[str] = []
    images: list[str] = []
    files = ["dast/staging.log"]
    try:
        if not _network(run, net, log):
            return _error("cannot create the staging network", files)
        containers, err = start_services(run, net, c.staging_services, "staging", outdir, log)
        if err:
            return _error(f"staging service {err}", files + [f"dast/{s}.log" for s in c.staging_services
                                                              if (outdir / f"{s}.log").exists()])
        for comp in c.companions:
            tag = f"gmshield-ci/{c.service}-{comp.target}:{run.sha}"
            if _buildx(run, log, "--target", comp.target, "-t", tag, "--load",
                       timeout=run.s.limit("build", 1800)) != 0:
                return _error(f"companion '{comp.target}' failed to build", files)
            images.append(tag)
            rc = run.docker.run(f"companion-{comp.alias}", tag, [], log=log, timeout=120, network=net,
                                env={"GMSHIELD_MODE": "test"}, user=None, detach=True,
                                extra=["--network-alias", comp.alias])
            containers.append(_cname(run, f"companion-{comp.alias}"))
            if rc != 0:
                return _error(f"companion '{comp.target}' failed to start", files)
        certs = None
        if c.certs:
            certs = staging_certs(run, ["app", c.service])
            if certs is None:
                return _error("could not create the throwaway certificates", files)
        argv = container_args(c, run.s, "staging", name=app, image=run.local_image, network=net,
                              labels=run.docker.labels, mounts_dir=_mount_dirs(c, run.work / "mounts"),
                              certs_dir=certs)
        if sh(argv, log, 120) != 0:
            return _error("staging container failed to start", files)
        scheme = c.health_scheme
        ca = certs / "ca.crt" if scheme == "https" and certs else None
        if not _probe(run, net, f"{scheme}://app:{c.port}{c.health_path}", log, ca):
            container_logs(app, outdir / "app.log")
            return _error(f"app not healthy at {c.health_path} within {run.s.limit('startup', 180)}s",
                          files + ["dast/app.log"] + _service_logs(c.staging_services, containers, outdir))
        result = _zap(run, net, f"{scheme}://app:{c.port}", outdir, active=True)
        container_logs(app, outdir / "app.log")
        result[2].append("dast/app.log")
        return result
    finally:
        _remove(app, *containers)
        sh(["docker", "network", "rm", net], None, 60)
        for tag in images:
            sh(["docker", "rmi", tag], None, 120)


# ------------------------------------------------------------------ integration tests

def integration_tests(run: "Run"):
    """develop (full): build the contract's [test].target stage and run it beside throwaway services."""
    c = run.contract
    if not c.integration_target:
        return _skip("no integration tests declared ([test].target)")
    if not c.has_dockerfile:
        return _skip("no Dockerfile yet")
    outdir = run.dir / "integration-tests"
    outdir.mkdir(parents=True, exist_ok=True)
    log = outdir / "integration-tests.log"
    files = ["integration-tests/integration-tests.log"]
    tag = f"gmshield-ci/{c.service}-{c.integration_target}:{run.sha}"
    if _buildx(run, log, "--target", c.integration_target, "-t", tag, "--load",
               timeout=run.s.limit("build", 1800)) != 0:
        return _error(f"stage '{c.integration_target}' failed to build", files)
    net = f"gmshield-ci-{run.id}-it"
    containers: list[str] = []
    try:
        if not _network(run, net, log):
            return _error("cannot create the integration-test network", files)
        containers, err = start_services(run, net, c.test_services, "it", outdir, log)
        if err:
            return _error(f"test service {err}", files + [f"integration-tests/{s}.log" for s in c.test_services
                                                          if (outdir / f"{s}.log").exists()])
        limit = run.s.limit("integration_tests", 1800)
        rc = run.docker.run("integration", tag, [], log=log, timeout=limit, network=net,
                            env={"GMSHIELD_MODE": "test"}, user=None)
        files += _service_logs(c.test_services, containers, outdir)
        if rc == 124:
            return _error(f"integration tests timed out after {limit}s", files)
        if rc != 0:
            return _error(f"integration tests failed (exit {rc})", files)
        return "ok", {"exit_code": 0, "services": c.test_services}, files, "passed"
    finally:
        _remove(*containers)
        sh(["docker", "network", "rm", net], None, 60)
        sh(["docker", "rmi", tag], None, 120)


def dast_production(run: "Run"):
    """main: passive baseline scan of the freshly deployed production container."""
    c = run.contract
    if not c.http:
        return _skip("no HTTP port declared")
    if not run.deployed:
        return _skip("nothing deployed")
    return _zap(run, c.prod_networks(run.s)[0], f"{c.health_scheme}://{run.prod_name}:{c.port}",
                run.dir / "dast-post-deploy", active=False)


# ------------------------------------------------------------------ main-only stages

def promotion(run: "Run"):
    rec = run.promotions.get(run.repo.name, {}).get(run.tree)
    if rec:
        return "ok", {"promoted": True, **rec}, [], f"same code passed develop in run {rec['run']}"
    return "ok", {"promoted": False}, [], "this exact code has not passed the develop quality gate"


def publish(run: "Run"):
    if not run.image_built:
        return _skip("no image")
    log = run.dir / "publish.log"
    for cmd in (["docker", "tag", run.local_image, run.prod_image], ["docker", "push", run.prod_image]):
        if sh(cmd, log, 900) != 0:
            return _error(f"{cmd[1]} failed", ["publish.log"])
    digests = (inspect(run.prod_image, "{{range .RepoDigests}}{{println .}}{{end}}") or "").split()
    repo = run.prod_image.rsplit(":", 1)[0]
    digest = next((d for d in digests if d.startswith(repo + "@")), None)
    return "ok", {"image": run.prod_image, "digest": digest}, ["publish.log"], digest or run.prod_image


def _start_prod(run: "Run", image_ref: str, log: Path) -> tuple[int, str]:
    """Replace the production container. Returns (exit code, reason on failure)."""
    c = run.contract
    nets = c.prod_networks(run.s)
    sh(["docker", "rm", "-f", run.prod_name], log, 120)
    env_file = run.s.secrets_dir / f"{c.service}.env"   # server-only secrets, never in git
    mounts = run.s.mounts_root / c.service
    if c.mounts:
        _mount_dirs(c, mounts)
    argv = container_args(c, run.s, "production", name=run.prod_name, image=image_ref, network=nets[0],
                          env_file=env_file if env_file.is_file() else None, mounts_dir=mounts,
                          certs_dir=run.s.certs_dir if c.certs else None, create=len(nets) > 1)
    rc = sh(argv, log, 300)
    if rc != 0 or len(nets) == 1:
        return rc, "" if rc == 0 else f"docker exit {rc}"
    for n in nets[1:]:
        rc = sh(["docker", "network", "connect", n, run.prod_name], log, 60)
        if rc != 0:
            return rc, f"cannot connect to network {n}"
    rc = sh(["docker", "start", run.prod_name], log, 120)
    return rc, "" if rc == 0 else f"docker start exit {rc}"


def _ca_cert(run: "Run") -> Path | None:
    return run.s.certs_dir / "ca.crt" if run.contract.health_scheme == "https" else None


def _healthy(run: "Run", log: Path) -> bool:
    c = run.contract
    if c.http:
        return _probe(run, c.prod_networks(run.s)[0],
                      f"{c.health_scheme}://{run.prod_name}:{c.port}{c.health_path}", log, _ca_cert(run))
    return container_healthy(run.prod_name)


def _missing_networks(nets: list[str]) -> list[str]:
    return [n for n in nets if capture(["docker", "network", "inspect", n])[0] != 0]


def deploy(run: "Run"):
    if not run.image_built:
        return _skip("no image")
    c = run.contract
    log = run.dir / "deploy.log"
    # Checked before anything changes: production keeps running when the contract cannot be met.
    missing = _missing_networks(c.prod_networks(run.s))
    if missing:
        return _error(f"network {', '.join(missing)} does not exist; production unchanged", [])
    ca = _ca_cert(run)
    if ca is not None and not ca.is_file():
        return _error(f"{ca} missing (needed by health_scheme = \"https\"); production unchanged", [])
    run.previous_image = inspect(run.prod_name, "{{.Config.Image}}")
    rc, why = _start_prod(run, run.prod_image, log)
    if rc == 0 and _healthy(run, log):
        run.deployed = True
        return "ok", {"container": run.prod_name, "image": run.prod_image,
                      "previous": run.previous_image}, ["deploy.log"], f"{run.prod_name} -> {run.prod_image}"
    container_logs(run.prod_name, run.dir / "deploy-app.log")
    rolled = rollback(run, log)
    return _error(f"new version {why or 'unhealthy'}; {rolled}", ["deploy.log", "deploy-app.log"])


def rollback(run: "Run", log: Path) -> str:
    if run.previous_image:
        rc, _ = _start_prod(run, run.previous_image, log)
        run.rolled_back = rc == 0
        return f"rolled back to {run.previous_image}" if rc == 0 else "ROLLBACK FAILED"
    sh(["docker", "rm", "-f", run.prod_name], log, 120)
    run.rolled_back = True
    return "no previous version; container removed"


def mark_prod(run: "Run"):
    """After a fully passed release, move the :prod tag to this image."""
    if not run.image_built:
        return
    prod_tag = run.prod_image.rsplit(":", 1)[0] + ":prod"
    log = run.dir / "publish.log"
    sh(["docker", "tag", run.prod_image, prod_tag], log, 120)
    sh(["docker", "push", prod_tag], log, 600)


def image_id(ref: str) -> str | None:
    rc, out = capture(["docker", "image", "inspect", "--format", "{{.Id}}", ref])
    return out if rc == 0 else None


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2, default=str))
