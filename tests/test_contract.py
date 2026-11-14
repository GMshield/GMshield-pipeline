"""The pipeline contract: every option, its validation, the docker arguments it produces, and the
runtime behaviour around them (with Docker replaced by a recorder). Run: python3 -m unittest -v"""
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from gmshield_ci import config, dockerops, pipeline, stages
from gmshield_ci.config import ContractError, container_args, load_contract

FIX = Path(__file__).parent / "fixtures"
SHA = "0123456789abcdef0123456789abcdef01234567"
RUN_ID = "20261113-120000-01234567"


def settings(home: Path = Path("/srv/ci"), **limits) -> config.Settings:
    return config.Settings(
        home=home, org="GMshield", branches=("develop", "main"), registry="localhost:5000",
        prod_network="rpg_default", ci_slice="ci.slice", repos=[],
        images={"zap": "zap@sha256:1", "postgres": "postgres@sha256:2", "redis": "redis@sha256:3",
                "jdk27": "jdk@sha256:4"},
        semgrep_rulesets=[], limits=limits, gates={})


def contract_from(text: str, dockerfile: str | None = None, repo: str = "GMshield-x") -> config.Contract:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / ".gmshield").mkdir()
        (Path(d) / ".gmshield" / "pipeline.toml").write_text(text)
        if dockerfile is not None:
            (Path(d) / "Dockerfile").write_text(dockerfile)
        return load_contract(Path(d), repo)


def fixture_contract(name: str) -> config.Contract:
    return contract_from((FIX / "contracts" / f"{name}.toml").read_text(), repo=f"GMshield-{name}")


def prod_args(c, s=None, env_file=None, **kw):
    s = s or settings()
    return container_args(c, s, "production", name=f"gmshield-{c.service}",
                          image=f"localhost:5000/gmshield-{c.service}:{SHA}", network=c.prod_networks(s)[0],
                          env_file=env_file, **kw)


def staging_args(c, s=None, **kw):
    s = s or settings()
    labels = dockerops.Docker(s.ci_slice, RUN_ID, "inst").labels
    return container_args(c, s, "staging", name=f"gmshield-ci-{RUN_ID}-app", image=f"gmshield-ci/{c.service}:{SHA}",
                          network=f"gmshield-ci-{RUN_ID}", labels=labels, **kw)


def old_prod(service, port, host_port, env=(), env_file=None):
    """Production arguments exactly as the pipeline built them before the contract grew."""
    cmd = ["docker", "run", "-d", "--name", f"gmshield-{service}", "--network", "rpg_default",
           "--restart", "unless-stopped", "--label", f"gmshield.service={service}", "--label", f"gmshield.sha={SHA}"]
    if port and host_port:
        cmd += ["-p", f"127.0.0.1:{host_port}:{port}"]
    for k, v in env:
        cmd += ["-e", f"{k}={v}"]
    if env_file:
        cmd += ["--env-file", env_file]
    return cmd + [f"localhost:5000/gmshield-{service}:{SHA}"]


def old_staging(service, env=()):
    """Staging arguments as Docker.run built them before, plus the one addition: GMSHIELD_MODE=test."""
    cmd = ["docker", "run", "--name", f"gmshield-ci-{RUN_ID}-app", "--label", "gmshield-ci=1",
           "--label", "gmshield-ci.instance=inst", "--label", f"gmshield-ci.run={RUN_ID}",
           "--cgroup-parent", "ci.slice", "-d", "--network", f"gmshield-ci-{RUN_ID}"]
    for k, v in env:
        cmd += ["-e", f"{k}={v}"]
    return cmd + ["-e", "GMSHIELD_MODE=test", "--network-alias", "app", f"gmshield-ci/{service}:{SHA}"]


# ------------------------------------------------------------------ today's contracts: unchanged arguments

class GoldenArgsTest(unittest.TestCase):
    def test_backend(self):
        c = fixture_contract("backend")
        self.assertEqual(prod_args(c), old_prod("backend", 8080, 8080))
        self.assertEqual(prod_args(c, env_file=Path("/srv/ci/secrets/backend.env")),
                         old_prod("backend", 8080, 8080, env_file="/srv/ci/secrets/backend.env"))
        self.assertEqual(staging_args(c), old_staging("backend"))

    def test_frontend(self):
        c = fixture_contract("frontend")
        self.assertEqual(prod_args(c), old_prod("frontend", 3000, 3000))
        self.assertEqual(staging_args(c), old_staging("frontend"))

    def test_worker(self):
        c = fixture_contract("worker")
        self.assertFalse(c.http)
        self.assertEqual(prod_args(c), old_prod("worker", 0, 0))

    def test_sample_app(self):
        c = load_contract(FIX / "sample-app", "GMshield-sample")
        self.assertEqual(prod_args(c), old_prod("sample", 8080, 18080))
        self.assertEqual(staging_args(c), old_staging("sample"))

    def test_env_order_is_kept(self):
        c = contract_from('[service]\nname="x"\nport=80\n[deploy]\nenv={ B = "2", A = "1" }\n')
        self.assertEqual(prod_args(c), old_prod("x", 80, 0, env=[("B", "2"), ("A", "1")]))
        self.assertEqual(staging_args(c), old_staging("x", env=[("B", "2"), ("A", "1")]))

    def test_staging_matches_docker_run_of_before(self):
        """The old staging call went through Docker.run; replay it and compare."""
        c = fixture_contract("backend")
        seen = []
        with mock.patch.object(dockerops, "sh", lambda cmd, *a, **k: seen.append(cmd) or 0):
            dockerops.Docker("ci.slice", RUN_ID, "inst").run(
                "app", f"gmshield-ci/backend:{SHA}", [], log=Path("/dev/null"), timeout=120,
                network=f"gmshield-ci-{RUN_ID}", env=dict(c.env), user=None, detach=True,
                extra=["--network-alias", "app"])
        new = staging_args(c)
        i = new.index("GMSHIELD_MODE=test")
        self.assertEqual(new[:i - 1] + new[i + 1:], seen[0])

    def test_template_shows_the_defaults(self):
        c = contract_from((config.RUNNER_DIR / "templates" / "pipeline.toml").read_text(), repo="GMshield-backend")
        d = config.Contract(present=True, service="backend")
        self.assertEqual(c, d)

    def test_defaults(self):
        c = fixture_contract("backend")
        self.assertEqual((c.health_scheme, c.memory, c.cpus, c.slice, c.networks, c.mounts, c.tmpfs, c.certs,
                          c.read_only, c.user, c.cap_drop, c.staging_env, c.staging_services, c.companions,
                          c.integration_target, c.test_services),
                         ("http", "", "", "", [], [], [], False, False, "", [], {}, [], [], "", []))
        self.assertEqual(c.prod_networks(settings()), ["rpg_default"])


# ------------------------------------------------------------------ one test per option

HARDENED = '''
[service]
name = "api"
port = 8443
health_scheme = "https"
[deploy]
read_only = true
user = "10001:10001"
cap_drop = ["ALL"]
memory = "768m"
cpus = 1.5
slice = "containers.slice"
tmpfs = ["/tmp", "/run/app:size=16m"]
networks = ["gmshield-app", "gmshield-data"]
mounts = [{ name = "uploads", target = "/data/uploads" }, { name = "seed", target = "/seed", read_only = true }]
certs = true
'''


class OptionTest(unittest.TestCase):
    def opt(self, deploy: str, service: str = "port = 80"):
        return contract_from(f'[service]\nname="x"\n{service}\n[deploy]\n{deploy}\n')

    def extra(self, c, role="production", **kw):
        """The arguments an option adds after the ones every container gets."""
        base = (prod_args if role == "production" else staging_args)(contract_from('[service]\nname="x"\nport=80\n'))
        got = (prod_args if role == "production" else staging_args)(c, **kw)
        self.assertEqual(got[:len(base) - 1], base[:-1])
        self.assertEqual(got[-1], base[-1])
        return got[len(base) - 1:-1]

    def test_health_scheme(self):
        self.assertEqual(self.opt("certs = true", 'port = 80\nhealth_scheme = "https"').health_scheme, "https")
        with self.assertRaisesRegex(ContractError, r"\[service\].health_scheme"):
            self.opt("", 'port = 80\nhealth_scheme = "ftp"')
        with self.assertRaisesRegex(ContractError, "needs \\[deploy\\].certs"):
            self.opt("", 'port = 80\nhealth_scheme = "https"')

    def test_memory(self):
        self.assertEqual(self.extra(self.opt('memory = "512m"')), ["--memory", "512m"])
        for bad in ('"lots"', '"-1g"', "512"):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].memory"):
                self.opt(f"memory = {bad}")

    def test_cpus(self):
        self.assertEqual(self.extra(self.opt("cpus = 2")), ["--cpus", "2"])
        self.assertEqual(self.extra(self.opt("cpus = 0.5")), ["--cpus", "0.5"])
        for bad in ("0", "true", '"many"', "[1]"):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].cpus"):
                self.opt(f"cpus = {bad}")

    def test_slice(self):
        self.assertEqual(self.extra(self.opt('slice = "ai.slice"')), ["--cgroup-parent", "ai.slice"])
        self.assertEqual(self.extra(self.opt('slice = "ai.slice"'), "staging"), [])   # staging: CI slice only
        for bad in ("ci.slice", "system.slice", "../x"):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].slice.*unknown slice"):
                self.opt(f'slice = "{bad}"')

    def test_networks(self):
        c = self.opt('networks = ["gmshield-app", "gmshield-data"]')
        self.assertEqual(c.prod_networks(settings()), ["gmshield-app", "gmshield-data"])
        args = prod_args(c, create=True)
        self.assertEqual(args[:3], ["docker", "create", "--name"])
        self.assertNotIn("-d", args)
        self.assertEqual(args[args.index("--network") + 1], "gmshield-app")
        self.assertEqual(staging_args(c)[staging_args(c).index("--network") + 1], f"gmshield-ci-{RUN_ID}")
        for bad in ('["host"]', '["none"]', '["a", "a"]', '["a b"]', '[1]', '"net"'):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].networks"):
                self.opt(f"networks = {bad}")

    def test_mounts(self):
        c = self.opt('mounts = [{ name = "uploads", target = "/data" }, { name = "seed", target = "/s", read_only = true }]')
        self.assertEqual(self.extra(c, mounts_dir=Path("/srv/ci/mounts/x")),
                         ["-v", "/srv/ci/mounts/x/uploads:/data:rw", "-v", "/srv/ci/mounts/x/seed:/s:ro"])
        for bad in ('"../etc"', '"a/b"', '"/abs"', '".."', '"a..b"', "1"):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].mounts\[0\].name"):
                self.opt(f'mounts = [{{ name = {bad}, target = "/data" }}]')
        for bad in ('"data"', '"/"', '"/a/../b"', '"/a:rw"', '"/a,b"'):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].mounts\[0\].target"):
                self.opt(f'mounts = [{{ name = "d", target = {bad} }}]')
        with self.assertRaisesRegex(ContractError, r"mounts\[0\]"):
            self.opt('mounts = [{ name = "d", target = "/d", source = "/etc" }]')
        with self.assertRaisesRegex(ContractError, "used twice"):
            self.opt('mounts = [{ name = "d", target = "/d" }, { name = "d", target = "/e" }]')

    def test_tmpfs(self):
        self.assertEqual(self.extra(self.opt('tmpfs = ["/tmp", "/run:size=16m,mode=1777"]')),
                         ["--tmpfs", "/tmp", "--tmpfs", "/run:size=16m,mode=1777"])
        for bad in ('["tmp"]', '["/a b"]', '[3]'):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].tmpfs"):
                self.opt(f"tmpfs = {bad}")

    def test_certs(self):
        c = self.opt("certs = true")
        self.assertEqual(self.extra(c, certs_dir=Path("/srv/ci/certs")),
                         ["-v", "/srv/ci/certs:/run/gmshield/certs:ro"])
        with self.assertRaisesRegex(ContractError, r"\[deploy\].certs"):
            self.opt('certs = "yes"')

    def test_read_only(self):
        self.assertEqual(self.extra(self.opt("read_only = true")),
                         ["--read-only", "--security-opt", "no-new-privileges"])
        with self.assertRaisesRegex(ContractError, r"\[deploy\].read_only"):
            self.opt("read_only = 1")

    def test_user(self):
        self.assertEqual(self.extra(self.opt('user = "10001:10001"')),
                         ["--user", "10001:10001", "--security-opt", "no-new-privileges"])
        for bad in ('"a b"', '"1:2:3"', "10001"):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].user"):
                self.opt(f"user = {bad}")

    def test_cap_drop(self):
        self.assertEqual(self.extra(self.opt('cap_drop = ["ALL"]')),
                         ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"])
        for bad in ("[1]", '["all"]', '["NET_RAW --privileged"]', '"ALL"'):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].cap_drop"):
                self.opt(f"cap_drop = {bad}")

    def test_no_privilege_escalation_options_exist(self):
        """Unknown [deploy] keys are not passed through: nothing can ask for --privileged or --cap-add."""
        c = self.opt('privileged = true\ncap_add = ["SYS_ADMIN"]\nnetwork_mode = "host"')
        joined = " ".join(prod_args(c) + staging_args(c))
        for flag in ("--privileged", "--cap-add", "--network host", "SYS_ADMIN"):
            self.assertNotIn(flag, joined)

    def test_staging_env(self):
        c = self.opt('env = { A = "prod" }\n[staging]\nenv = { A = "staging", B = "2" }')
        args = staging_args(c)
        self.assertEqual([args[i + 1] for i, a in enumerate(args) if a == "-e"],
                         ["A=staging", "B=2", "GMSHIELD_MODE=test"])
        self.assertNotIn("B=2", prod_args(c))

    def test_staging_services(self):
        c = self.opt('[staging]\nservices = ["postgres", "redis", "postgres"]')
        self.assertEqual(c.staging_services, ["postgres", "redis"])
        with self.assertRaisesRegex(ContractError, r"\[staging\].services: unknown service 'mysql'"):
            self.opt('[staging]\nservices = ["mysql"]')

    def test_staging_companions(self):
        c = self.opt('[[staging.companions]]\ntarget = "Stand-In-Backend"\nalias = "stand-in-backend"')
        self.assertEqual(c.companions, [config.Companion("stand-in-backend", "stand-in-backend")])
        for bad in ('target = "x"\nalias = "app"', 'target = "x"\nalias = "Bad_Alias"',
                    'target = "a b"\nalias = "x"', 'target = "x"'):
            with self.assertRaisesRegex(ContractError, r"\[staging\].companions\[0\]"):
                self.opt(f"[[staging.companions]]\n{bad}")

    def test_test_target_and_services(self):
        c = self.opt('[test]\ntarget = "integration"\nservices = ["postgres"]')
        self.assertEqual((c.integration_target, c.test_services), ("integration", ["postgres"]))
        with self.assertRaisesRegex(ContractError, r"\[test\].services"):
            self.opt('[test]\nservices = ["kafka"]')
        with self.assertRaisesRegex(ContractError, r"\[test\].target"):
            self.opt('[test]\ntarget = "../x"')

    def test_hardened_production_args(self):
        c = contract_from(HARDENED, repo="GMshield-api")
        args = prod_args(c, mounts_dir=Path("/srv/ci/mounts/api"), certs_dir=Path("/srv/ci/certs"), create=True)
        self.assertEqual(args, [
            "docker", "create", "--name", "gmshield-api", "--network", "gmshield-app", "--restart", "unless-stopped",
            "--label", "gmshield.service=api", "--label", f"gmshield.sha={SHA}",
            "--read-only", "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "768m", "--cpus", "1.5", "--cgroup-parent", "containers.slice",
            "--tmpfs", "/tmp", "--tmpfs", "/run/app:size=16m",
            "-v", "/srv/ci/mounts/api/uploads:/data/uploads:rw", "-v", "/srv/ci/mounts/api/seed:/seed:ro",
            "-v", "/srv/ci/certs:/run/gmshield/certs:ro", f"localhost:5000/gmshield-api:{SHA}"])

    def test_staging_has_production_hardening_in_ci_slice(self):
        c = contract_from(HARDENED, repo="GMshield-api")
        args = staging_args(c, mounts_dir=Path("/w/mounts"), certs_dir=Path("/w/certs"))
        for flag in ("--read-only", "--cap-drop", "--memory", "--cpus", "--tmpfs", "--security-opt"):
            self.assertIn(flag, args)
        self.assertEqual([args[i + 1] for i, a in enumerate(args) if a == "--cgroup-parent"], ["ci.slice"])

    def test_mounts_need_a_folder(self):
        c = self.opt('mounts = [{ name = "d", target = "/d" }]')
        with self.assertRaises(ValueError):
            prod_args(c)


class ForbiddenTest(unittest.TestCase):
    def test_gmshield_mode_in_any_env_table(self):
        for text, key in (('[deploy]\nenv = { GMSHIELD_MODE = "test" }', r"\[deploy\].env.GMSHIELD_MODE"),
                          ('[staging]\nenv = { GMSHIELD_MODE = "prod" }', r"\[staging\].env.GMSHIELD_MODE")):
            with self.assertRaisesRegex(ContractError, key):
                contract_from(text)

    def test_invalid_toml_and_tables(self):
        with self.assertRaisesRegex(ContractError, "not valid TOML"):
            contract_from("[deploy\n")
        with self.assertRaisesRegex(ContractError, r"\[staging\] must be a table"):
            contract_from('staging = "x"')
        with self.assertRaisesRegex(ContractError, "pipeline.toml"):
            contract_from('[service]\nport = "eighty"')

    def test_resolve_fails_naming_the_key(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "src"

            def export(mirror, sha, dest):
                (dest / ".gmshield").mkdir(parents=True)
                (dest / ".gmshield" / "pipeline.toml").write_text('[deploy]\nslice = "system.slice"\n')

            run = types.SimpleNamespace(mirror=Path(d), sha=SHA, src=src, repo=types.SimpleNamespace(name="GMshield-x"),
                                        contract=config.Contract())
            with mock.patch.object(pipeline.gitops, "export", export):
                outcome, metrics, _, detail = pipeline._resolve(run)
        self.assertEqual(outcome, "error")
        self.assertIn("[deploy].slice", detail)
        self.assertEqual(run.contract.service, "")          # nothing else learns from a refused contract


# ------------------------------------------------------------------ runtime behaviour, Docker recorded

class FakeDocker(dockerops.Docker):
    def __init__(self, rc=None):
        super().__init__("ci.slice", RUN_ID, "inst")
        self.calls = []
        self.rc = rc or {}

    def run(self, name, image, args, **kw):
        self.calls.append((name, image, args, kw))
        return self.rc.get(name, 0)


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cmds = []
        self.capture_rc = {}
        self.fail_once = set()
        self.patches = [
            mock.patch.object(stages, "sh", self.fake_sh),
            mock.patch.object(stages, "capture", self.fake_capture),
            mock.patch.object(stages, "container_logs", lambda name, dest: Path(dest).write_text("log")),
            mock.patch.object(stages, "inspect", lambda *a: "localhost:5000/gmshield-api:old"),
            mock.patch.object(stages, "_zap", lambda run, net, base, outdir, active:
                              ("ok", {"base": base, "net": net}, [], "zap")),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def fake_sh(self, cmd, log=None, timeout=600, env=None, cwd=None):
        self.cmds.append(cmd)
        if cmd[0] == "openssl":
            return subprocess.run(cmd, capture_output=True).returncode
        key = " ".join(cmd[:3])
        rc = self.capture_rc.get(key, 0)
        if key in self.fail_once:
            self.capture_rc.pop(key, None)
        return rc

    def fake_capture(self, cmd, timeout=120):
        self.cmds.append(cmd)
        if cmd[:3] == ["docker", "network", "inspect"]:
            return self.capture_rc.get(f"inspect {cmd[3]}", 0), ""
        if cmd[:2] == ["docker", "exec"]:
            return self.capture_rc.get("exec", 0), "PONG" if "redis-cli" in cmd else "accepting connections"
        return 0, ""

    def run_for(self, text, dockerfile="FROM a AS test\nFROM a AS stand-in-backend\nFROM a AS integration\nFROM b\n",
                **limits):
        s = settings(self.tmp / "home", **limits)
        c = contract_from(text, dockerfile, repo="GMshield-api")
        d = self.tmp / "artifacts"
        d.mkdir(exist_ok=True)
        return types.SimpleNamespace(
            s=s, contract=c, id=RUN_ID, sha=SHA, dir=d, work=self.tmp / "work", src=self.tmp / "src",
            docker=FakeDocker(), local_image=f"gmshield-ci/api:{SHA}", prod_image=f"localhost:5000/gmshield-api:{SHA}",
            prod_name="gmshield-api", image_built=True, deployed=False, rolled_back=False, previous_image=None,
            repo=types.SimpleNamespace(url="file:///x"))

    def docker_cmds(self, verb):
        return [c for c in self.cmds if c[:2] == ["docker", verb]]

    # -- hardened production with two networks
    def test_deploy_creates_connects_then_starts(self):
        (self.tmp / "home" / "certs").mkdir(parents=True)
        (self.tmp / "home" / "certs" / "ca.crt").write_text("ca")
        run = self.run_for(HARDENED)
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "ok", detail)
        order = [c[1] for c in self.cmds if c[:1] == ["docker"] and c[1] in ("rm", "create", "network", "start")]
        self.assertEqual(order, ["network", "network", "rm", "create", "network", "start"])   # 2 inspects first
        self.assertEqual(self.docker_cmds("network")[-1], ["docker", "network", "connect", "gmshield-data", "gmshield-api"])
        for name in ("uploads", "seed"):
            d = self.tmp / "home" / "mounts" / "api" / name
            self.assertEqual(d.stat().st_mode & 0o777, 0o700)
        name, image, args, kw = run.docker.calls[-1]                 # the HTTPS probe
        self.assertEqual(kw["network"], "gmshield-app")              # the app's own network only
        self.assertIn("--cacert /certs/ca.crt", args[2])
        self.assertIn("https://gmshield-api:8443/", args[2])
        self.assertEqual(kw["mounts"], [(self.tmp / "home" / "certs" / "ca.crt", "/certs/ca.crt", "ro")])

    def test_missing_network_is_named_and_production_untouched(self):
        self.capture_rc["inspect gmshield-data"] = 1
        run = self.run_for('[service]\nport = 80\n[deploy]\nnetworks = ["gmshield-app", "gmshield-data"]\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("gmshield-data", detail)
        self.assertEqual(self.docker_cmds("rm") + self.docker_cmds("create"), [])

    def test_connect_failure_rolls_back(self):
        self.capture_rc["docker network connect"] = 1
        self.fail_once.add("docker network connect")
        run = self.run_for('[service]\nport = 80\n[deploy]\nnetworks = ["gmshield-app", "gmshield-data"]\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("cannot connect to network gmshield-data", detail)
        self.assertIn("rolled back to localhost:5000/gmshield-api:old", detail)
        self.assertEqual(len(self.docker_cmds("start")), 1)            # only the previous version started

    def test_missing_ca_is_a_deploy_error(self):
        run = self.run_for('[service]\nport = 443\nhealth_scheme = "https"\n[deploy]\ncerts = true\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("ca.crt", detail)
        self.assertEqual(self.docker_cmds("rm"), [])

    def test_default_deploy_uses_docker_run(self):
        run = self.run_for('[service]\nport = 80\n')
        self.assertEqual(stages.deploy(run)[0], "ok")
        self.assertEqual(self.docker_cmds("run")[0][:3], ["docker", "run", "-d"])
        self.assertEqual(self.docker_cmds("start"), [])
        self.assertEqual(run.docker.calls[-1][3]["network"], "rpg_default")

    def test_post_deploy_dast_uses_first_network(self):
        run = self.run_for('[service]\nport = 80\n[deploy]\nnetworks = ["gmshield-app", "gmshield-data"]\n')
        run.deployed = True
        _, m, _, _ = stages.dast_production(run)
        self.assertEqual((m["net"], m["base"]), ("gmshield-app", "http://gmshield-api:80"))

    # -- staging
    STAGING = ('[service]\nport = 80\n[staging]\nservices = ["postgres", "redis"]\n'
               '[[staging.companions]]\ntarget = "stand-in-backend"\nalias = "stand-in-backend"\n')

    def test_staging_services_companion_then_app(self):
        run = self.run_for(self.STAGING)
        outcome, _, _, detail = stages.dast_staging(run)
        self.assertEqual(outcome, "ok", detail)
        names = [c[0] for c in run.docker.calls]
        self.assertEqual(names, ["staging-postgres", "staging-redis", "companion-stand-in-backend", "probe"])
        pg = run.docker.calls[0]
        self.assertEqual(pg[3]["network"], f"gmshield-ci-{RUN_ID}")
        self.assertEqual(pg[3]["env"], {"POSTGRES_DB": "gmshield", "POSTGRES_USER": "gmshield",
                                        "POSTGRES_PASSWORD": "gmshield-test-mode"})
        self.assertEqual(pg[3]["extra"][:2], ["--network-alias", "postgres"])
        self.assertEqual(run.docker.calls[1][3]["extra"][:2], ["--network-alias", "redis"])
        build = next(c for c in self.cmds if c[:3] == ["docker", "buildx", "build"])
        self.assertIn("stand-in-backend", build[build.index("--target") + 1])
        app = next(c for c in self.docker_cmds("run"))
        self.assertIn("GMSHIELD_MODE=test", app)
        ready = [c for c in self.cmds if c[:2] == ["docker", "exec"]]
        self.assertTrue(any("pg_isready" in c for c in ready) and any("redis-cli" in c for c in ready))
        removed = self.docker_cmds("rm")[-1]
        self.assertEqual(removed[:4], ["docker", "rm", "-f", "-v"])
        for n in ("app", "staging-postgres", "staging-redis", "companion-stand-in-backend"):
            self.assertIn(f"gmshield-ci-{RUN_ID}-{n}", removed)
        self.assertIn(["docker", "network", "rm", f"gmshield-ci-{RUN_ID}"], self.cmds)
        self.assertIn(["docker", "rmi", f"gmshield-ci/api-stand-in-backend:{SHA}"], self.cmds)

    def test_staging_service_not_ready(self):
        self.capture_rc["exec"] = 1
        run = self.run_for(self.STAGING, startup=0)
        outcome, _, files, detail = stages.dast_staging(run)
        self.assertEqual(outcome, "error")
        self.assertIn("not ready", detail)
        self.assertIn("dast/postgres.log", files)
        self.assertNotIn("probe", [c[0] for c in run.docker.calls])
        self.assertIn(["docker", "network", "rm", f"gmshield-ci-{RUN_ID}"], self.cmds)

    def test_companion_build_failure(self):
        self.capture_rc["docker buildx build"] = 1
        run = self.run_for(self.STAGING)
        outcome, _, _, detail = stages.dast_staging(run)
        self.assertEqual((outcome, detail), ("error", "companion 'stand-in-backend' failed to build"))

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_staging_https_uses_a_throwaway_ca(self):
        run = self.run_for('[service]\nport = 443\nhealth_scheme = "https"\n[deploy]\ncerts = true\n')
        outcome, m, _, detail = stages.dast_staging(run)
        self.assertEqual(outcome, "ok", detail)
        certs = run.work / "staging-certs"
        self.assertEqual(sorted(p.name for p in certs.iterdir()), ["ca.crt", "tls.crt", "tls.key"])
        self.assertFalse((certs / "ca.key").exists())
        verify = subprocess.run(["openssl", "verify", "-CAfile", certs / "ca.crt", certs / "tls.crt"],
                                capture_output=True, text=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        text = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName", "-in", certs / "tls.crt"],
                              capture_output=True, text=True).stdout
        self.assertIn("DNS:app", text)
        app = self.docker_cmds("run")[0]
        self.assertIn(f"{certs}:/run/gmshield/certs:ro", app)
        probe = run.docker.calls[-1]
        self.assertIn("--cacert /certs/ca.crt", probe[2][2])
        self.assertIn("https://app:443/", probe[2][2])
        self.assertEqual(probe[3]["mounts"], [(certs / "ca.crt", "/certs/ca.crt", "ro")])
        self.assertEqual(m["base"], "https://app:443")

    # -- integration tests
    IT = '[service]\nport = 80\n[test]\ntarget = "integration"\nservices = ["postgres"]\n'

    def test_integration_tests_pass(self):
        run = self.run_for(self.IT)
        outcome, m, _, detail = stages.integration_tests(run)
        self.assertEqual(outcome, "ok", detail)
        build = next(c for c in self.cmds if c[:3] == ["docker", "buildx", "build"])
        self.assertEqual(build[build.index("--target") + 1], "integration")
        svc, test = run.docker.calls
        self.assertEqual((svc[0], svc[3]["network"]), ("it-postgres", f"gmshield-ci-{RUN_ID}-it"))
        self.assertEqual((test[0], test[1]), ("integration", f"gmshield-ci/api-integration:{SHA}"))
        self.assertEqual((test[3]["network"], test[3]["env"]), (f"gmshield-ci-{RUN_ID}-it", {"GMSHIELD_MODE": "test"}))
        self.assertEqual(test[3]["timeout"], 1800)
        create = next(c for c in self.cmds if c[:3] == ["docker", "network", "create"])
        self.assertIn("--internal", create)
        self.assertIn(["docker", "network", "rm", f"gmshield-ci-{RUN_ID}-it"], self.cmds)

    def test_integration_tests_fail_or_time_out(self):
        for rc, words in ((1, "failed (exit 1)"), (124, "timed out after 60s")):
            run = self.run_for(self.IT, integration_tests=60)
            run.docker.rc = {"integration": rc}
            outcome, _, files, detail = stages.integration_tests(run)
            self.assertEqual(outcome, "error")
            self.assertIn(words, detail)
            self.assertIn("integration-tests/postgres.log", files)

    def test_integration_tests_skipped_without_target(self):
        run = self.run_for('[service]\nport = 80\n')
        self.assertEqual(stages.integration_tests(run)[0], "skipped")
        self.assertEqual(self.cmds, [])


class FlowTest(unittest.TestCase):
    def test_develop_full_runs_integration_tests_after_image(self):
        order = []
        run = types.SimpleNamespace(mode="full", old=None, sha=SHA, records=[], notes=[], id=RUN_ID, tree="t",
                                    repo=types.SimpleNamespace(name="GMshield-x"),
                                    s=types.SimpleNamespace(state_dir=Path(tempfile.mkdtemp())))
        self.addCleanup(shutil.rmtree, run.s.state_dir, ignore_errors=True)
        with mock.patch.object(pipeline, "_source_checks", lambda *a, **k: None), \
                mock.patch.object(pipeline.stages, "execute", lambda run, key, *a: order.append(key) or []):
            pipeline.develop_flow(run)
        self.assertEqual(order, ["sonar", "image", "integration_tests", "dast"])


class ToolsTest(unittest.TestCase):
    def test_throwaway_images_are_pinned(self):
        import tomllib
        tools = tomllib.loads((config.RUNNER_DIR / "tools.toml").read_text())
        for name in ("postgres", "redis", "jdk27"):
            self.assertRegex(tools["images"][name], r"^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")
        self.assertEqual(tools["limits"]["integration_tests"], 1800)
        self.assertEqual(set(stages.SERVICE_SPECS), set(config.SERVICES))

    def test_service_credentials_match_backend_test_mode(self):
        """GMshield-backend's application-test-mode.yaml fixes these; the pipeline must match them."""
        pg = stages.SERVICE_SPECS["postgres"]["env"]
        self.assertEqual((pg["POSTGRES_DB"], pg["POSTGRES_USER"], pg["POSTGRES_PASSWORD"]),
                         ("gmshield", "gmshield", "gmshield-test-mode"))
        self.assertNotIn("--requirepass", stages.SERVICE_SPECS["redis"]["args"])


if __name__ == "__main__":
    unittest.main()
