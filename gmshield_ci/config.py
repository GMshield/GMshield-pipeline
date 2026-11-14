"""Settings (where things live, what to watch) and the per-repo pipeline contract."""
from __future__ import annotations

import hashlib
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

RUNNER_DIR = Path(__file__).resolve().parent.parent


def read_toml(path: Path) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


@dataclass(frozen=True)
class Repo:
    name: str
    url: str


@dataclass
class Settings:
    home: Path
    org: str
    branches: tuple[str, ...]
    registry: str
    prod_network: str
    ci_slice: str
    repos: list[Repo]
    images: dict[str, str]
    semgrep_rulesets: list[str]
    limits: dict
    gates: dict

    @property
    def mirrors(self) -> Path: return self.home / "mirrors"
    @property
    def work(self) -> Path: return self.home / "work"
    @property
    def state_dir(self) -> Path: return self.home / "state"
    @property
    def artifacts(self) -> Path: return self.home / "artifacts"
    @property
    def cache(self) -> Path: return self.home / "cache"
    @property
    def secrets_dir(self) -> Path: return self.home / "secrets"
    @property
    def mounts_root(self) -> Path: return self.home / "mounts"      # <mounts_root>/<service>/<name>
    @property
    def certs_dir(self) -> Path: return self.home / "certs"         # mounted read-only when certs = true

    @property
    def instance(self) -> str:
        """Identifies this pipeline installation (by its home folder) on a shared Docker host,
        so cleaning up after a crash never touches another installation's or a test's containers."""
        return hashlib.sha1(str(self.home.resolve()).encode()).hexdigest()[:12]

    def limit(self, key: str, default: int) -> int:
        return int(self.limits.get(key, default))


def load_settings() -> Settings:
    """Environment overrides exist for testing: GMSHIELD_HOME, GMSHIELD_REPOS, GMSHIELD_GATES."""
    home = Path(os.environ.get("GMSHIELD_HOME", str(Path.home() / "gmshield-ci")))
    cfg = read_toml(Path(os.environ.get("GMSHIELD_REPOS", str(RUNNER_DIR / "repos.toml"))))
    tools = read_toml(RUNNER_DIR / "tools.toml")
    gates = read_toml(Path(os.environ.get("GMSHIELD_GATES", str(RUNNER_DIR / "gates.toml"))))
    org = cfg["org"]
    repos = [Repo(r["name"], r.get("url") or f"https://github.com/{org}/{r['name']}.git")
             for r in cfg.get("repo", [])]
    return Settings(
        home=home, org=org,
        branches=tuple(cfg.get("branches", ["develop", "main"])),
        registry=cfg.get("registry", "localhost:5000"),
        prod_network=cfg.get("prod_network", "rpg_default"),
        ci_slice=cfg.get("ci_slice", "ci.slice"),
        repos=repos, images=tools["images"],
        semgrep_rulesets=tools.get("semgrep", {}).get("rulesets", ["p/default"]),
        limits=tools.get("limits", {}), gates=gates,
    )


# ---------------------------------------------------------------- per-repo contract

class ContractError(ValueError):
    """A .gmshield/pipeline.toml the pipeline refuses; the message names the offending key."""


SLICES = ("containers.slice", "ai.slice")      # [deploy].slice; staging always runs in the CI slice
SERVICES = ("postgres", "redis")               # throwaway services for staging and integration tests
MODE_VAR = "GMSHIELD_MODE"                     # set by the pipeline only (test and staging runs)
CERTS_TARGET = "/run/gmshield/certs"           # where the certificates folder appears in the app
RESERVED_ALIASES = ("app", "probe", "zap", *SERVICES)

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")          # mount names, networks, users, stages
_ALIAS = re.compile(r"[a-z0-9][a-z0-9-]*")
_PATH = re.compile(r"/[A-Za-z0-9_./-]*")                   # absolute container paths, no ':' or ','
_TMPFS = re.compile(r"/[A-Za-z0-9_./-]*(:[A-Za-z0-9_=,.-]+)?")
_MEMORY = re.compile(r"[1-9][0-9]*[bkmg]?")
_USER = re.compile(r"[A-Za-z0-9_.-]+(:[A-Za-z0-9_.-]+)?")
_CAP = re.compile(r"[A-Z][A-Z_]*")


@dataclass(frozen=True)
class Mount:
    name: str          # source: <home>/mounts/<service>/<name> (production), a per-run folder (staging)
    target: str        # absolute path inside the container
    read_only: bool = False


@dataclass(frozen=True)
class Companion:
    target: str        # Dockerfile stage built and run beside the app in staging
    alias: str         # its name on the run's network


@dataclass
class Contract:
    """What an app repo tells the pipeline, from .gmshield/pipeline.toml (all optional)."""
    present: bool = False
    service: str = ""
    port: int = 0                 # HTTP port inside the container; 0 = no HTTP (no DAST)
    health_path: str = "/"
    health_scheme: str = "http"   # "https": probes verify the app's certificate against ca.crt
    dockerfile: str = "Dockerfile"
    context: str = "."
    test_target: str = "test"     # Dockerfile stage that runs unit tests
    dast_path: str = "/"
    openapi: str = ""             # e.g. /v3/api-docs -> ZAP API scan on develop
    host_port: int = 0            # 127.0.0.1:<host_port> in production; 0 = not published
    env: dict = field(default_factory=dict)
    self_update: bool = False     # GMshield-pipeline only: deploying = updating the runner itself
    # [deploy]: resources, placement and hardening (production and staging alike)
    memory: str = ""              # e.g. "512m"; "" = no limit
    cpus: str = ""                # e.g. "1.5"; "" = no limit
    slice: str = ""               # production cgroup slice; "" = Docker's default
    networks: list[str] = field(default_factory=list)   # production networks; [] = the pipeline's prod network
    mounts: list[Mount] = field(default_factory=list)
    tmpfs: list[str] = field(default_factory=list)
    certs: bool = False
    read_only: bool = False
    user: str = ""
    cap_drop: list[str] = field(default_factory=list)
    # [staging]
    staging_env: dict = field(default_factory=dict)
    staging_services: list[str] = field(default_factory=list)
    companions: list[Companion] = field(default_factory=list)
    # [test]
    integration_target: str = ""  # Dockerfile stage run as integration tests; "" = stage skipped
    test_services: list[str] = field(default_factory=list)
    dockerfile_stages: list[str] = field(default_factory=list)
    has_dockerfile: bool = False

    @property
    def http(self) -> bool:
        return self.port > 0

    @property
    def hardened(self) -> bool:
        """Any hardening option set: then no-new-privileges is added as well."""
        return self.read_only or bool(self.user) or bool(self.cap_drop)

    def prod_networks(self, s: Settings) -> list[str]:
        return list(self.networks) or [s.prod_network]


_FROM = re.compile(r"^\s*FROM\s+\S+(?:\s+AS\s+([A-Za-z0-9_.-]+))?", re.IGNORECASE | re.MULTILINE)


def _table(data: dict, key: str) -> dict:
    v = data.get(key, {})
    if not isinstance(v, dict):
        raise ContractError(f"[{key}] must be a table")
    return v


def _str(t: dict, sect: str, key: str, default: str, pattern: re.Pattern | None = None) -> str:
    v = t.get(key, default)
    if not isinstance(v, str):
        raise ContractError(f"[{sect}].{key} must be a string")
    if v and pattern is not None and not pattern.fullmatch(v):
        raise ContractError(f"[{sect}].{key} = {v!r} is not allowed")
    return v


def _bool(t: dict, sect: str, key: str) -> bool:
    v = t.get(key, False)
    if not isinstance(v, bool):
        raise ContractError(f"[{sect}].{key} must be true or false")
    return v


def _list(t: dict, sect: str, key: str) -> list:
    v = t.get(key, [])
    if not isinstance(v, list):
        raise ContractError(f"[{sect}].{key} must be a list")
    return v


def _strings(t: dict, sect: str, key: str, pattern: re.Pattern) -> list[str]:
    out = []
    for v in _list(t, sect, key):
        if not isinstance(v, str) or not pattern.fullmatch(v) or ".." in v:
            raise ContractError(f"[{sect}].{key}: {v!r} is not allowed")
        out.append(v)
    return out


def _env(t: dict, sect: str) -> dict:
    v = t.get("env", {})
    if not isinstance(v, dict):
        raise ContractError(f"[{sect}].env must be a table")
    if MODE_VAR in v:
        raise ContractError(f"[{sect}].env.{MODE_VAR}: set by the pipeline only, never in a contract")
    return {str(k): str(x) for k, x in v.items()}


def _services(t: dict, sect: str) -> list[str]:
    out = []
    for v in _list(t, sect, "services"):
        if v not in SERVICES:
            raise ContractError(f"[{sect}].services: unknown service {v!r} (known: {', '.join(SERVICES)})")
        if v not in out:
            out.append(v)
    return out


def _parse(c: Contract, data: dict) -> None:
    svc, build = _table(data, "service"), _table(data, "build")
    dast, deploy = _table(data, "dast"), _table(data, "deploy")
    staging, test = _table(data, "staging"), _table(data, "test")
    c.service = re.sub(r"[^a-z0-9-]", "-", str(svc.get("name", c.service)).lower())
    c.port = int(svc.get("port", 0))
    c.health_path = str(svc.get("health_path", "/"))
    c.health_scheme = _str(svc, "service", "health_scheme", "http")
    if c.health_scheme not in ("http", "https"):
        raise ContractError(f"[service].health_scheme = {c.health_scheme!r}: use \"http\" or \"https\"")
    c.dockerfile = str(build.get("dockerfile", "Dockerfile"))
    c.context = str(build.get("context", "."))
    c.test_target = str(build.get("test_target", "test"))
    c.dast_path = str(dast.get("path", "/"))
    c.openapi = str(dast.get("openapi", ""))
    c.host_port = int(deploy.get("host_port", 0))
    c.env = _env(deploy, "deploy")
    c.self_update = bool(deploy.get("self_update", False))

    c.memory = _str(deploy, "deploy", "memory", "", _MEMORY)
    cpus = deploy.get("cpus", "")
    if isinstance(cpus, bool) or not isinstance(cpus, (int, float, str)):
        raise ContractError("[deploy].cpus must be a number")
    if cpus != "":
        try:
            ok = 0 < float(cpus) <= 64
        except ValueError:
            ok = False
        if not ok:
            raise ContractError(f"[deploy].cpus = {cpus!r} is not allowed")
        c.cpus = str(cpus)
    c.slice = _str(deploy, "deploy", "slice", "")
    if c.slice and c.slice not in SLICES:
        raise ContractError(f"[deploy].slice: unknown slice {c.slice!r} (allowed: {', '.join(SLICES)})")
    c.networks = _strings(deploy, "deploy", "networks", _NAME)
    for n in c.networks:
        if n in ("host", "none"):
            raise ContractError(f"[deploy].networks: {n!r} is not allowed")
    if len(set(c.networks)) != len(c.networks):
        raise ContractError("[deploy].networks: a network is listed twice")
    c.tmpfs = _strings(deploy, "deploy", "tmpfs", _TMPFS)
    c.certs = _bool(deploy, "deploy", "certs")
    c.read_only = _bool(deploy, "deploy", "read_only")
    c.user = _str(deploy, "deploy", "user", "", _USER)
    c.cap_drop = _strings(deploy, "deploy", "cap_drop", _CAP)
    for i, m in enumerate(_list(deploy, "deploy", "mounts")):
        key = f"[deploy].mounts[{i}]"
        if not isinstance(m, dict) or set(m) - {"name", "target", "read_only"}:
            raise ContractError(f"{key} must be a table with name, target and optionally read_only")
        name, target, ro = m.get("name"), m.get("target"), m.get("read_only", False)
        if not isinstance(name, str) or not _NAME.fullmatch(name) or ".." in name:
            raise ContractError(f"{key}.name = {name!r}: a plain name, never a path")
        if not isinstance(target, str) or not _PATH.fullmatch(target) or ".." in target or target == "/":
            raise ContractError(f"{key}.target = {target!r}: an absolute path inside the container")
        if not isinstance(ro, bool):
            raise ContractError(f"{key}.read_only must be true or false")
        c.mounts.append(Mount(name, target, ro))
    if len({m.name for m in c.mounts}) != len(c.mounts):
        raise ContractError("[deploy].mounts: a name is used twice")
    if c.health_scheme == "https" and not c.certs:
        raise ContractError("[service].health_scheme = \"https\" needs [deploy].certs = true")

    c.staging_env = _env(staging, "staging")
    c.staging_services = _services(staging, "staging")
    for i, comp in enumerate(_list(staging, "staging", "companions")):
        key = f"[staging].companions[{i}]"
        if not isinstance(comp, dict) or set(comp) - {"target", "alias"}:
            raise ContractError(f"{key} must be a table with target and alias")
        target, alias = comp.get("target"), comp.get("alias")
        if not isinstance(target, str) or not _NAME.fullmatch(target):
            raise ContractError(f"{key}.target = {target!r} is not a Dockerfile stage name")
        if not isinstance(alias, str) or not _ALIAS.fullmatch(alias) or alias in RESERVED_ALIASES:
            raise ContractError(f"{key}.alias = {alias!r} is not allowed")
        c.companions.append(Companion(target.lower(), alias))
    if len({x.alias for x in c.companions}) != len(c.companions):
        raise ContractError("[staging].companions: an alias is used twice")

    c.integration_target = _str(test, "test", "target", "", _NAME).lower()
    c.test_services = _services(test, "test")


def load_contract(src: Path, repo_name: str) -> Contract:
    """Raises ContractError when the contract asks for something the pipeline refuses."""
    c = Contract(service=re.sub(r"^gmshield-", "", repo_name.lower()))
    path = src / ".gmshield" / "pipeline.toml"
    if path.is_file():
        try:
            data = read_toml(path)
        except tomllib.TOMLDecodeError as e:
            raise ContractError(f".gmshield/pipeline.toml is not valid TOML: {e}") from None
        c.present = True
        try:
            _parse(c, data)
        except (TypeError, ValueError) as e:
            if isinstance(e, ContractError):
                raise
            raise ContractError(f".gmshield/pipeline.toml: {e}") from None
    df = (src / c.context / c.dockerfile).resolve()
    if df.is_file() and src.resolve() in df.parents:
        c.has_dockerfile = True
        c.dockerfile_stages = [m.group(1).lower() for m in _FROM.finditer(df.read_text(errors="replace"))
                               if m.group(1)]
    return c


# ---------------------------------------------------------------- docker run arguments

def container_args(c: Contract, s: Settings, role: str, *, name: str, image: str, network: str,
                   labels: Sequence[str] = (), env_file: Path | None = None,
                   mounts_dir: Path | None = None, certs_dir: Path | None = None,
                   create: bool = False) -> list[str]:
    """The one place that turns a contract into `docker run` (or `docker create`) arguments. Pure.

    role "production": the live container on `network` (the first of its networks); `create` makes it
    `docker create` so further networks can be connected before `docker start`.
    role "staging": the throwaway copy on a run's internal network, inside the CI slice, with
    GMSHIELD_MODE=test; `labels` are the run's labels.
    `mounts_dir` holds one folder per mount name; `certs_dir` is mounted read-only at CERTS_TARGET.
    """
    verb = ["docker", "create"] if create else ["docker", "run"]
    detach = [] if create else ["-d"]
    if role == "production":
        cmd = [*verb, *detach, "--name", name, "--network", network, "--restart", "unless-stopped",
               "--label", f"gmshield.service={c.service}", "--label", f"gmshield.sha={image.rsplit(':', 1)[-1]}"]
        if c.http and c.host_port:
            cmd += ["-p", f"127.0.0.1:{c.host_port}:{c.port}"]
        for k, v in c.env.items():
            cmd += ["-e", f"{k}={v}"]
        if env_file is not None:
            cmd += ["--env-file", str(env_file)]
    elif role == "staging":
        cmd = [*verb, "--name", name, *labels, "--cgroup-parent", s.ci_slice, *detach, "--network", network]
        for k, v in {**c.env, **c.staging_env, MODE_VAR: "test"}.items():
            cmd += ["-e", f"{k}={v}"]
        cmd += ["--network-alias", "app"]
    else:
        raise ValueError(f"unknown role {role!r}")
    if c.read_only:
        cmd += ["--read-only"]
    if c.user:
        cmd += ["--user", c.user]
    for cap in c.cap_drop:
        cmd += ["--cap-drop", cap]
    if c.hardened:
        cmd += ["--security-opt", "no-new-privileges"]
    if c.memory:
        cmd += ["--memory", c.memory]
    if c.cpus:
        cmd += ["--cpus", c.cpus]
    if role == "production" and c.slice:
        cmd += ["--cgroup-parent", c.slice]
    for t in c.tmpfs:
        cmd += ["--tmpfs", t]
    if c.mounts:
        if mounts_dir is None:
            raise ValueError("mounts declared but no mounts folder given")
        for m in c.mounts:
            cmd += ["-v", f"{mounts_dir / m.name}:{m.target}:{'ro' if m.read_only else 'rw'}"]
    if certs_dir is not None:
        cmd += ["-v", f"{certs_dir}:{CERTS_TARGET}:ro"]
    return cmd + [image]
