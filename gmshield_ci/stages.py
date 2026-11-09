"""Pipeline stages. Each returns (outcome, metrics, files, detail); outcome is ok | error | skipped."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from . import gates
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
                   detail=metrics.get("details", {}).get(g, detail), seconds=seconds)
        if g:
            r.status, r.threshold, r.reasons = gates.judge(g, outcome, metrics, run.s.gates)
        else:
            r.status = {"ok": "passed", "skipped": "skipped"}.get(outcome, "failed")
            if outcome == "error":
                r.reasons = [metrics.get("error", detail or "error")]
        run.log(f"stage end: {r.title}: {r.status} ({seconds}s) {'; '.join(r.reasons)}")
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


def sast(run: "Run"):
    args = ["semgrep", "scan"]
    for rs in run.s.semgrep_rulesets:
        args += ["--config", rs]
    args += ["--metrics=off", "--disable-version-check", "--json-output=/out/semgrep.json",
             "--sarif-output=/out/semgrep.sarif", "--timeout=30", "--jobs=2", "--max-memory=1500", "/src"]
    rc = run.docker.run("semgrep", run.s.images["semgrep"], args, log=run.dir / "semgrep.log",
                        timeout=run.s.limit("semgrep", 1200),
                        mounts=[(run.src, "/src", "ro"), (run.dir, "/out", "rw")],
                        env={"HOME": "/tmp", "SEMGREP_SEND_METRICS": "off"}, workdir="/src")
    out = run.dir / "semgrep.json"
    if rc not in (0, 1) or not out.exists():
        return _error(f"semgrep exit {rc}", ["semgrep.log"])
    m = gates.parse_semgrep(out)
    return "ok", m, ["semgrep.json", "semgrep.sarif", "semgrep.log"], \
        f"high {m['high']}, medium {m['medium']}, low {m['low']}"


def _trivy(run: "Run", name: str, args: list[str], extra_mounts=()) -> int:
    run.s.cache.joinpath("trivy").mkdir(parents=True, exist_ok=True)
    return run.docker.run(
        name, run.s.images["trivy"],
        [args[0], "--cache-dir", "/cache", "--skip-version-check", "--no-progress", "--timeout", "15m", *args[1:]],
        log=run.dir / "trivy.log", timeout=run.s.limit("trivy", 1200),
        mounts=[(run.dir, "/out", "rw"), (run.s.cache / "trivy", "/cache", "rw"), *extra_mounts],
        env={"HOME": "/tmp"}, workdir="/src" if args[0] == "fs" else None)


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

def _probe(run: "Run", network: str, url: str, log: Path) -> bool:
    """Wait for the app from inside its Docker network (works for internal networks too)."""
    tries = max(1, run.s.limit("startup", 180) // 3)
    rc = run.docker.run("probe", run.s.images["zap"],
                        ["sh", "-c", f"for i in $(seq 1 {tries}); do curl -fsS -o /dev/null '{url}' && exit 0; "
                                     f"sleep 3; done; exit 1"],
                        log=log, timeout=run.s.limit("startup", 180) + 60, network=network, user=None,
                        entrypoint="")
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


def dast_staging(run: "Run"):
    """develop: run the new image in an isolated, internet-less network and attack it (active scan)."""
    c = run.contract
    if not c.http:
        return _skip("no HTTP port declared (.gmshield/pipeline.toml [service].port)")
    if not run.image_built:
        return _skip("no image to test")
    outdir = run.dir / "dast"
    outdir.mkdir(parents=True, exist_ok=True)
    net = f"gmshield-ci-{run.id}"
    sh(["docker", "network", "create", "--internal", "--label", "gmshield-ci=1", "--label", run.docker.label, net],
       outdir / "staging.log", 60)
    env = dict(c.env)
    rc = run.docker.run("app", run.local_image, [], log=outdir / "staging.log", timeout=120, network=net,
                        env=env, user=None, detach=True, extra=["--network-alias", "app"])
    app = f"gmshield-ci-{run.id}-app"
    if rc != 0:
        return _error("staging container failed to start", ["dast/staging.log"])
    try:
        if not _probe(run, net, f"http://app:{c.port}{c.health_path}", outdir / "staging.log"):
            container_logs(app, outdir / "app.log")
            return _error(f"app not healthy at {c.health_path} within {run.s.limit('startup', 180)}s",
                          ["dast/staging.log", "dast/app.log"])
        result = _zap(run, net, f"http://app:{c.port}", outdir, active=True)
        container_logs(app, outdir / "app.log")
        result[2].append("dast/app.log")
        return result
    finally:
        sh(["docker", "rm", "-f", app], None, 60)
        sh(["docker", "network", "rm", net], None, 60)


def dast_production(run: "Run"):
    """main: passive baseline scan of the freshly deployed production container."""
    c = run.contract
    if not c.http:
        return _skip("no HTTP port declared")
    if not run.deployed:
        return _skip("nothing deployed")
    return _zap(run, run.s.prod_network, f"http://{run.prod_name}:{c.port}", run.dir / "dast-post-deploy",
                active=False)


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


def _start_prod(run: "Run", image_ref: str, log: Path) -> int:
    c = run.contract
    sh(["docker", "rm", "-f", run.prod_name], log, 120)
    cmd = ["docker", "run", "-d", "--name", run.prod_name, "--network", run.s.prod_network,
           "--restart", "unless-stopped", "--label", f"gmshield.service={c.service}",
           "--label", f"gmshield.sha={image_ref.rsplit(':', 1)[-1]}"]
    if c.http and c.host_port:
        cmd += ["-p", f"127.0.0.1:{c.host_port}:{c.port}"]
    for k, v in c.env.items():
        cmd += ["-e", f"{k}={v}"]
    env_file = run.s.secrets_dir / f"{c.service}.env"   # server-only secrets, never in git
    if env_file.is_file():
        cmd += ["--env-file", str(env_file)]
    return sh(cmd + [image_ref], log, 300)


def _healthy(run: "Run", log: Path) -> bool:
    c = run.contract
    if c.http:
        return _probe(run, run.s.prod_network, f"http://{run.prod_name}:{c.port}{c.health_path}", log)
    return container_healthy(run.prod_name)


def deploy(run: "Run"):
    if not run.image_built:
        return _skip("no image")
    log = run.dir / "deploy.log"
    run.previous_image = inspect(run.prod_name, "{{.Config.Image}}")
    if _start_prod(run, run.prod_image, log) == 0 and _healthy(run, log):
        run.deployed = True
        return "ok", {"container": run.prod_name, "image": run.prod_image,
                      "previous": run.previous_image}, ["deploy.log"], f"{run.prod_name} -> {run.prod_image}"
    container_logs(run.prod_name, run.dir / "deploy-app.log")
    rolled = rollback(run, log)
    return _error(f"new version unhealthy; {rolled}", ["deploy.log", "deploy-app.log"])


def rollback(run: "Run", log: Path) -> str:
    if run.previous_image:
        rc = _start_prod(run, run.previous_image, log)
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
