"""Settings (where things live, what to watch) and the per-repo pipeline contract."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

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

@dataclass
class Contract:
    """What an app repo tells the pipeline, from .gmshield/pipeline.toml (all optional)."""
    present: bool = False
    service: str = ""
    port: int = 0                 # HTTP port inside the container; 0 = no HTTP (no DAST)
    health_path: str = "/"
    dockerfile: str = "Dockerfile"
    context: str = "."
    test_target: str = "test"     # Dockerfile stage that runs unit tests
    dast_path: str = "/"
    openapi: str = ""             # e.g. /v3/api-docs -> ZAP API scan on develop
    host_port: int = 0            # 127.0.0.1:<host_port> in production; 0 = not published
    env: dict = field(default_factory=dict)
    dockerfile_stages: list[str] = field(default_factory=list)
    has_dockerfile: bool = False

    @property
    def http(self) -> bool:
        return self.port > 0


_FROM = re.compile(r"^\s*FROM\s+\S+(?:\s+AS\s+([A-Za-z0-9_.-]+))?", re.IGNORECASE | re.MULTILINE)


def load_contract(src: Path, repo_name: str) -> Contract:
    c = Contract(service=re.sub(r"^gmshield-", "", repo_name.lower()))
    path = src / ".gmshield" / "pipeline.toml"
    if path.is_file():
        data = read_toml(path)
        c.present = True
        svc, build = data.get("service", {}), data.get("build", {})
        dast, deploy = data.get("dast", {}), data.get("deploy", {})
        c.service = re.sub(r"[^a-z0-9-]", "-", str(svc.get("name", c.service)).lower())
        c.port = int(svc.get("port", 0))
        c.health_path = str(svc.get("health_path", "/"))
        c.dockerfile = str(build.get("dockerfile", "Dockerfile"))
        c.context = str(build.get("context", "."))
        c.test_target = str(build.get("test_target", "test"))
        c.dast_path = str(dast.get("path", "/"))
        c.openapi = str(dast.get("openapi", ""))
        c.host_port = int(deploy.get("host_port", 0))
        c.env = {str(k): str(v) for k, v in deploy.get("env", {}).items()}
    df = (src / c.context / c.dockerfile).resolve()
    if df.is_file() and src.resolve() in df.parents:
        c.has_dockerfile = True
        c.dockerfile_stages = [m.group(1).lower() for m in _FROM.finditer(df.read_text(errors="replace"))
                               if m.group(1)]
    return c
