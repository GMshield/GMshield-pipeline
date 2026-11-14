"""The pipeline contract: every option, its validation, the docker arguments it produces, and the
runtime behaviour around them (with Docker replaced by a recorder). Run: python3 -m unittest -v"""
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from gmshield_ci import config, dockerops, pipeline, sonar, stages
from gmshield_ci.config import ContractError, container_args, load_contract

FIX = Path(__file__).parent / "fixtures"
SHA = "0123456789abcdef0123456789abcdef01234567"
RUN_ID = "20261113-120000-01234567"


def settings(home: Path = Path("/srv/ci"), **limits) -> config.Settings:
    return config.Settings(
        home=home, org="GMshield", branches=("develop", "main"), registry="localhost:5000",
        prod_network="gmshield-app", ci_slice="ci.slice", repos=[],
        images={"zap": "zap@sha256:1", "postgres": "postgres@sha256:2", "redis": "redis@sha256:3",
                "jdk27": "jdk@sha256:4", "sonar_scanner": "scanner@sha256:5"},
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
    cmd = ["docker", "run", "-d", "--name", f"gmshield-{service}", "--network", "gmshield-app",
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
        self.assertEqual(c.prod_networks(settings()), ["gmshield-app"])


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
        self.assertEqual(self.extra(c), ["-v", "gmshield-x-uploads:/data:rw", "-v", "gmshield-x-seed:/s:ro"])
        self.assertEqual(self.extra(c, "staging", run_id=RUN_ID),
                         ["-v", f"gmshield-ci-{RUN_ID}-x-uploads:/data:rw", "-v", f"gmshield-ci-{RUN_ID}-x-seed:/s:ro"])
        for bad in ('"../etc"', '"a/b"', '"/abs"', '".."', '"a..b"', "1"):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].mounts\[0\].name"):
                self.opt(f'mounts = [{{ name = {bad}, target = "/data" }}]')
        for bad in ('"data"', '"/"', '"/."', '"//"', '"/./"', '"/a/../b"', '"/a:rw"', '"/a,b"'):
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
        args = prod_args(c, certs_dir=Path("/srv/ci/certs/api"), create=True)
        self.assertEqual(args, [
            "docker", "create", "--name", "gmshield-api", "--network", "gmshield-app", "--restart", "unless-stopped",
            "--label", "gmshield.service=api", "--label", f"gmshield.sha={SHA}",
            "--read-only", "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "768m", "--cpus", "1.5", "--cgroup-parent", "containers.slice",
            "--tmpfs", "/tmp", "--tmpfs", "/run/app:size=16m",
            "-v", "gmshield-api-uploads:/data/uploads:rw", "-v", "gmshield-api-seed:/seed:ro",
            "-v", "/srv/ci/certs/api:/run/gmshield/certs:ro", f"localhost:5000/gmshield-api:{SHA}"])

    def test_staging_has_production_hardening_in_ci_slice(self):
        c = contract_from(HARDENED, repo="GMshield-api")
        args = staging_args(c, run_id=RUN_ID, certs_dir=Path("/w/certs"))
        for flag in ("--read-only", "--cap-drop", "--memory", "--cpus", "--tmpfs", "--security-opt"):
            self.assertIn(flag, args)
        self.assertEqual([args[i + 1] for i, a in enumerate(args) if a == "--cgroup-parent"], ["ci.slice"])

    def test_staging_mounts_need_the_run(self):
        c = self.opt('mounts = [{ name = "d", target = "/d" }]')
        with self.assertRaises(ValueError):
            staging_args(c)


class ReviewPatchTest(unittest.TestCase):
    """Validation added after the first review: each refusal names its key."""
    def opt(self, deploy: str = "", service: str = "port = 80", rest: str = "", dockerfile=None):
        return contract_from(f'[service]\nname="x"\n{service}\n[deploy]\n{deploy}\n{rest}', dockerfile)

    def test_env_keys_must_be_variable_names(self):
        for sect in ("deploy", "staging"):
            for bad in ('"GMSHIELD_MODE=prod"', '"A B"', '"1A"', '"A-B"', '""'):
                with self.assertRaisesRegex(ContractError, rf"\[{sect}\].env"):
                    self.opt(rest=f"[{sect}]\nenv = {{ {bad} = \"x\" }}" if sect == "staging" else "",
                             deploy=f"env = {{ {bad} = \"x\" }}" if sect == "deploy" else "")
        with self.assertRaisesRegex(ContractError, r"\[deploy\].env.A must be a plain value"):
            self.opt('env = { A = [1] }')
        self.assertEqual(self.opt('env = { _A1 = 1 }').env, {"_A1": "1"})

    def test_cpus_minimum_and_normalised(self):
        for given, want in (("0.01", "0.01"), ('"1.50"', "1.5"), ("2.0", "2"), ('"3"', "3"), ("64", "64")):
            self.assertEqual(self.opt(f"cpus = {given}").cpus, want)
        for bad in ("0.0001", "0.009", '" 2"', '"1e1"', '"inf"', "inf", "nan", "65", "-1"):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].cpus"):
                self.opt(f"cpus = {bad}")

    def test_memory_minimum(self):
        for ok in ('"6m"', '"6291456"', '"6144k"', '"1g"', '"512m"'):
            self.assertEqual(self.opt(f"memory = {ok}").memory, ok.strip('"'))
        self.assertEqual((self.opt('memory = "512M"').memory, self.opt('memory = "1G"').memory), ("512m", "1g"))
        for bad in ('"1b"', '"5m"', '"6291455"', '" 512m"', '"512mb"', '"0m"', '"5M"'):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].memory"):
                self.opt(f"memory = {bad}")

    def test_duplicate_or_root_targets(self):
        cases = [
            ('mounts = [{ name = "a", target = "/d" }, { name = "b", target = "/d/" }]', r"\[deploy\].mounts: target"),
            ('mounts = [{ name = "a", target = "/d" }]\ntmpfs = ["/d:size=1m"]', r"\[deploy\].tmpfs: target '/d'"),
            ('tmpfs = ["/t", "//t"]', r"\[deploy\].tmpfs: target"),
            ('certs = true\ntmpfs = ["/run/gmshield/certs"]', r"\[deploy\].certs: target"),
            ('certs = true\nmounts = [{ name = "a", target = "/run/gmshield/./certs" }]', r"\[deploy\].certs"),
        ]
        for deploy, key in cases:
            with self.assertRaisesRegex(ContractError, key):
                self.opt(deploy)
        for bad in ('"/"', '"/."', '"//"', '"/:size=1m"'):
            with self.assertRaisesRegex(ContractError, r"\[deploy\].tmpfs"):
                self.opt(f"tmpfs = [{bad}]")
        self.assertEqual(self.opt('tmpfs = ["/run/gmshield"]\ncerts = true').tmpfs, ["/run/gmshield"])

    def test_ports(self):
        for key, sect in (("port", "service"), ("host_port", "deploy")):
            for bad in ("inf", "nan", '"80"', "8080.0", "-1", "65536", "true"):
                text = (f'[service]\nname="x"\n{key} = {bad}\n' if sect == "service"
                        else f'[service]\nname="x"\nport = 80\n[deploy]\n{key} = {bad}\n')
                with self.assertRaisesRegex(ContractError, rf"\[{sect}\].{key}"):
                    contract_from(text)
        self.assertEqual(self.opt("host_port = 65535", "port = 0").host_port, 65535)

    def test_service_name(self):
        for bad in ('""', '"---"', '"!!"', "1"):
            with self.assertRaisesRegex(ContractError, r"\[service\].name"):
                contract_from(f"[service]\nname = {bad}\n")
        self.assertEqual(contract_from('[service]\nname = "My App"\n').service, "my-app")

    def test_stages_must_exist_in_the_dockerfile(self):
        df = "FROM a AS test\nFROM a AS integration\nFROM b\n"
        with self.assertRaisesRegex(ContractError, r"\[staging\].companions\[0\].target = 'stand-in'.*no such stage"):
            self.opt(rest='[[staging.companions]]\ntarget = "stand-in"\nalias = "s"', dockerfile=df)
        with self.assertRaisesRegex(ContractError, r"\[test\].target = 'it'.*no such stage"):
            self.opt(rest='[test]\ntarget = "it"', dockerfile=df)
        self.assertEqual(self.opt(rest='[test]\ntarget = "Integration"', dockerfile=df).integration_target,
                         "integration")
        self.assertEqual(self.opt(rest='[test]\ntarget = "it"').integration_target, "it")   # no Dockerfile yet
        flagged = "FROM --platform=$BUILDPLATFORM a AS build\nfrom --platform=linux/amd64 --x=y b as Stand-In\nFROM c\n"
        c = self.opt(rest='[[staging.companions]]\ntarget = "stand-in"\nalias = "s"', dockerfile=flagged)
        self.assertEqual(c.dockerfile_stages, ["build", "stand-in"])

    def test_url_paths(self):
        for ok in ("/", "/actuator/health", "/api/health?full=1&x=y", "/a%20b", "/v3/api-docs:x"):
            self.assertEqual(self.opt(service=f'port = 80\nhealth_path = "{ok}"').health_path, ok)
            self.assertEqual(self.opt(rest=f'[dast]\npath = "{ok}"').dast_path, ok)
        for bad in ("health", "/a'b", "/a b", "/$(id)", "/a`b`", "/a;b'", '/a\\"', "", "/a\\nb"):
            with self.assertRaisesRegex(ContractError, r"\[service\].health_path"):
                self.opt(service=f'port = 80\nhealth_path = "{bad}"')
            with self.assertRaisesRegex(ContractError, r"\[dast\].path"):
                self.opt(rest=f'[dast]\npath = "{bad}"')


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
        with self.assertRaisesRegex(ContractError, r"\[service\].port"):
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
        self.inspected = {("gmshield-api", "{{.Config.Image}}"): "localhost:5000/gmshield-api:old",
                          ("gmshield-api", "{{.State.Running}}"): "true"}
        self.patches = [
            mock.patch.object(stages, "sh", self.fake_sh),
            mock.patch.object(stages, "capture", self.fake_capture),
            mock.patch.object(stages, "container_logs", lambda name, dest: Path(dest).write_text("log")),
            mock.patch.object(stages, "inspect", lambda obj, fmt: self.inspected.get((obj, fmt))),
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
        if "check" in cmd and str(stages.CERTS_SCRIPT) in cmd:           # the real certificate check
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout.strip()
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
            previous_kept=False, previous_running=False, repo=types.SimpleNamespace(url="file:///x"))

    def docker_cmds(self, verb):
        return [c for c in self.cmds if c[:2] == ["docker", verb]]

    # -- hardened production with two networks
    def certs(self, ca=True):
        d = self.tmp / "home" / "certs" / "api"
        d.mkdir(parents=True)
        if ca:
            (d / "ca.crt").write_text("ca")
        return d

    def prod_cmds(self):
        """Every docker command that touches containers, in order (network inspects excluded)."""
        return [c for c in self.cmds if c[:1] == ["docker"] and c[1] in ("rm", "stop", "rename", "create", "run",
                                                                           "start", "network")
                and c[:3] != ["docker", "network", "inspect"]]

    def test_deploy_creates_connects_then_starts(self):
        certs = self.certs()
        run = self.run_for(HARDENED)
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "ok", detail)
        inspects = [c[3] for c in self.cmds if c[:3] == ["docker", "network", "inspect"]]
        self.assertEqual(inspects, ["gmshield-app", "gmshield-data"])
        docker = [c for c in self.cmds if c[:1] == ["docker"]]
        self.assertEqual(docker.index(["docker", "network", "inspect", "gmshield-data"]), 1)   # checked first
        verbs = [c[:2] + ([c[2]] if c[1] == "network" else []) for c in self.prod_cmds()]
        self.assertEqual(verbs, [["docker", "stop"], ["docker", "rename"], ["docker", "rm"],
                                 ["docker", "create"], ["docker", "network", "connect"], ["docker", "start"]])
        self.assertIn(["docker", "rename", "gmshield-api", "gmshield-api-previous"], self.cmds)
        self.assertEqual(self.docker_cmds("network")[-1], ["docker", "network", "connect", "gmshield-data", "gmshield-api"])
        create = self.docker_cmds("create")[0]
        self.assertIn("gmshield-api-uploads:/data/uploads:rw", create)               # named volumes, no host path
        self.assertIn(f"{certs}:/run/gmshield/certs:ro", create)                     # this service's folder only
        self.assertFalse((self.tmp / "home" / "mounts").exists())
        self.assertTrue(run.previous_kept)                                           # kept until the release stands
        name, image, args, kw = run.docker.calls[-1]                 # the HTTPS probe
        self.assertEqual(kw["network"], "gmshield-app")              # the app's own network only
        self.assertIn("--cacert /certs/ca.crt", args[2])
        self.assertIn("https://gmshield-api:8443/", args[2])
        self.assertEqual(kw["mounts"], [(certs / "ca.crt", "/certs/ca.crt", "ro")])

    def test_missing_network_is_named_and_production_untouched(self):
        self.capture_rc["inspect gmshield-data"] = 1
        run = self.run_for('[service]\nport = 80\n[deploy]\nnetworks = ["gmshield-app", "gmshield-data"]\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("gmshield-data", detail)
        self.assertEqual(self.prod_cmds(), [])

    def test_connect_failure_restores_the_previous_container(self):
        self.capture_rc["docker network connect"] = 1
        self.fail_once.add("docker network connect")
        run = self.run_for('[service]\nport = 80\n[deploy]\nnetworks = ["gmshield-app", "gmshield-data"]\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("cannot connect to network gmshield-data", detail)
        self.assertIn("rolled back to localhost:5000/gmshield-api:old", detail)
        cmds = self.prod_cmds()
        i = cmds.index(["docker", "network", "connect", "gmshield-data", "gmshield-api"])
        self.assertEqual(cmds[i + 1:], [["docker", "rm", "-f", "gmshield-api"],
                                        ["docker", "rename", "gmshield-api-previous", "gmshield-api"],
                                        ["docker", "start", "gmshield-api"]])   # the same container, not rebuilt
        self.assertEqual(len(self.docker_cmds("create")), 1)
        self.assertTrue(run.rolled_back)
        self.assertFalse(run.previous_kept)

    def test_unhealthy_restores_a_stopped_previous_as_stopped(self):
        self.inspected[("gmshield-api", "{{.State.Running}}")] = "false"
        run = self.run_for('[service]\nport = 80\n')
        run.docker.rc = {"probe": 1}
        outcome, _, files, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("unhealthy", detail)
        self.assertIn("deploy-app.log", files)
        self.assertEqual(self.prod_cmds()[-2:], [["docker", "rm", "-f", "gmshield-api"],
                                                 ["docker", "rename", "gmshield-api-previous", "gmshield-api"]])

    def test_no_previous_container_removes_the_new_one(self):
        self.inspected.clear()
        run = self.run_for('[service]\nport = 80\n')
        run.docker.rc = {"probe": 1}
        outcome, _, _, detail = stages.deploy(run)
        self.assertIn("no previous version; container removed", detail)
        self.assertEqual(self.docker_cmds("stop") + self.docker_cmds("rename"), [])
        self.assertEqual(self.prod_cmds()[-1], ["docker", "rm", "-f", "gmshield-api"])

    def test_previous_left_by_an_interrupted_deploy_is_the_rollback_target(self):
        self.inspected = {("gmshield-api-previous", "{{.Config.Image}}"): "localhost:5000/gmshield-api:older"}
        run = self.run_for('[service]\nport = 80\n')
        run.docker.rc = {"probe": 1}
        _, _, _, detail = stages.deploy(run)
        self.assertIn("rolled back to localhost:5000/gmshield-api:older", detail)
        self.assertNotIn(["docker", "rm", "-f", "gmshield-api-previous"], self.cmds)
        self.assertEqual(self.prod_cmds()[-2:], [["docker", "rename", "gmshield-api-previous", "gmshield-api"],
                                                 ["docker", "start", "gmshield-api"]])

    def test_both_containers_present_keeps_previous_as_the_target(self):
        """An interrupted deploy left the last good container aside: it stays the rollback target."""
        self.inspected[("gmshield-api-previous", "{{.Config.Image}}")] = "localhost:5000/gmshield-api:good"
        run = self.run_for('[service]\nport = 80\n')
        run.docker.rc = {"probe": 1}
        _, _, _, detail = stages.deploy(run)
        self.assertIn("rolled back to localhost:5000/gmshield-api:good", detail)
        self.assertNotIn(["docker", "rm", "-f", "gmshield-api-previous"], self.cmds)
        self.assertEqual(self.docker_cmds("stop") + [c for c in self.cmds if c[:3] == ["docker", "rename", "gmshield-api"]], [])
        self.assertEqual(self.prod_cmds()[0], ["docker", "rm", "-f", "gmshield-api"])   # the unverified one goes
        self.assertEqual(self.prod_cmds()[-2:], [["docker", "rename", "gmshield-api-previous", "gmshield-api"],
                                                 ["docker", "start", "gmshield-api"]])

    def test_rename_back_fails(self):
        self.capture_rc["docker rename gmshield-api-previous"] = 1
        run = self.run_for('[service]\nport = 80\n')
        run.docker.rc = {"probe": 1}
        _, _, _, detail = stages.deploy(run)
        self.assertIn("ROLLBACK FAILED", detail)
        self.assertEqual((run.rolled_back, run.previous_kept), (False, True))

    def test_restart_of_previous_fails(self):
        self.capture_rc["docker start gmshield-api"] = 1
        run = self.run_for('[service]\nport = 80\n')
        run.docker.rc = {"probe": 1}
        _, _, _, detail = stages.deploy(run)
        self.assertIn("ROLLBACK FAILED", detail)
        self.assertEqual((run.rolled_back, run.previous_kept), (False, True))

    def test_stop_fails_production_unchanged(self):
        self.capture_rc["docker stop gmshield-api"] = 1
        for running, starts in (("true", [["docker", "start", "gmshield-api"]]), ("false", [])):
            self.cmds.clear()
            self.inspected[("gmshield-api", "{{.State.Running}}")] = running
            run = self.run_for('[service]\nport = 80\n')
            outcome, _, _, detail = stages.deploy(run)
            self.assertEqual(outcome, "error")
            self.assertIn("cannot stop the current container; production unchanged", detail)
            self.assertEqual(self.docker_cmds("start"), starts)       # a stopped container is not started
            self.assertEqual(self.docker_cmds("rename") + self.docker_cmds("create") + self.docker_cmds("run"), [])

    def test_log_collection_failure_still_rolls_back(self):
        def boom(name, dest):
            raise subprocess.TimeoutExpired("docker logs", 60)
        run = self.run_for('[service]\nport = 80\n')
        run.docker.rc = {"probe": 1}
        with mock.patch.object(stages, "container_logs", boom):
            outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("rolled back to localhost:5000/gmshield-api:old", detail)
        self.assertTrue(run.rolled_back)
        self.assertIn("could not collect the logs", (run.dir / "deploy-app.log").read_text())

    def test_current_container_that_cannot_be_set_aside_keeps_running(self):
        self.capture_rc["docker rename gmshield-api"] = 1
        run = self.run_for('[service]\nport = 80\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("production unchanged", detail)
        self.assertEqual(self.docker_cmds("create") + self.docker_cmds("run"), [])
        self.assertEqual(self.docker_cmds("start"), [["docker", "start", "gmshield-api"]])

    def test_deploy_warns_about_a_certificate_close_to_expiry_and_proceeds(self):
        home = self.tmp / "home"
        env = {"GMSHIELD_HOME": str(home), "PATH": "/usr/bin:/bin"}
        res = subprocess.run(["bash", str(stages.CERTS_SCRIPT), "issue"], capture_output=True, text=True, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        leaf = home / "certs" / "redis"
        csr, ext = self.tmp / "csr", self.tmp / "ext"
        ext.write_text("subjectAltName=DNS:redis\n")
        for cmd in (["openssl", "req", "-new", "-key", str(leaf / "tls.key"), "-subj", "/CN=redis", "-out", str(csr)],
                    ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(home / "ca" / "ca.crt"), "-CAkey",
                     str(home / "ca" / "ca.key"), "-set_serial", "9", "-days", "20", "-extfile", str(ext),
                     "-out", str(leaf / "tls.crt")]):
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
        run = self.run_for('[service]\nport = 80\n')
        outcome, metrics, _, _ = stages.deploy(run)
        self.assertEqual(outcome, "ok")
        self.assertEqual(len(metrics["warnings"]), 1)
        self.assertIn(f"{leaf / 'tls.crt'} expires on", metrics["warnings"][0])
        rec = stages.execute(types.SimpleNamespace(log=lambda m: None, lock=__import__("threading").Lock(),
                                                   records=[], titles={}, s=run.s),
                             "deploy", "Deploy (prd)", None, lambda r: (outcome, metrics, [], "ok"))[0]
        self.assertEqual(rec.status, "passed")
        self.assertEqual(rec.warnings, metrics["warnings"])

    def test_deploy_without_the_authority_runs_no_certificate_check(self):
        run = self.run_for('[service]\nport = 80\n')
        outcome, metrics, _, _ = stages.deploy(run)
        self.assertEqual(outcome, "ok")
        self.assertNotIn("warnings", metrics)
        self.assertFalse([c for c in self.cmds if str(stages.CERTS_SCRIPT) in c])

    def test_discard_previous(self):
        run = self.run_for('[service]\nport = 80\n')
        self.assertEqual(stages.deploy(run)[0], "ok")
        stages.discard_previous(run)
        self.assertEqual(self.cmds[-1], ["docker", "rm", "-f", "gmshield-api-previous"])
        self.assertFalse(run.previous_kept)
        n = len(self.cmds)
        stages.discard_previous(run)
        self.assertEqual(len(self.cmds), n)

    def test_missing_ca_is_a_deploy_error(self):
        self.certs(ca=False)
        run = self.run_for('[service]\nport = 443\nhealth_scheme = "https"\n[deploy]\ncerts = true\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("certs/api/ca.crt missing", detail)
        self.assertEqual(self.prod_cmds(), [])

    def test_missing_service_certs_folder_is_a_deploy_error(self):
        """Docker would otherwise create an empty, root-owned folder in its place."""
        (self.tmp / "home" / "certs").mkdir(parents=True)
        run = self.run_for('[service]\nport = 80\n[deploy]\ncerts = true\n')
        outcome, _, _, detail = stages.deploy(run)
        self.assertEqual(outcome, "error")
        self.assertIn("certs/api missing", detail)
        self.assertEqual(self.prod_cmds(), [])

    def test_default_deploy_uses_docker_run(self):
        run = self.run_for('[service]\nport = 80\n')
        self.assertEqual(stages.deploy(run)[0], "ok")
        self.assertEqual(self.docker_cmds("run")[0][:3], ["docker", "run", "-d"])
        self.assertEqual(self.docker_cmds("start"), [])
        self.assertEqual(run.docker.calls[-1][3]["network"], "gmshield-app")

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
        self.assertIn(f"gmshield-ci.run={RUN_ID}", build)                    # crash cleanup finds the image
        comp = run.docker.calls[2][3]
        self.assertEqual(comp["env"], {"GMSHIELD_MODE": "test"})

    def test_staging_mounts_are_run_labelled_volumes(self):
        run = self.run_for('[service]\nport = 80\n[deploy]\nuser = "10001"\n'
                           'mounts = [{ name = "uploads", target = "/data" }]\n')
        outcome, _, _, detail = stages.dast_staging(run)
        self.assertEqual(outcome, "ok", detail)
        vol = f"gmshield-ci-{RUN_ID}-api-uploads"
        create = self.docker_cmds("volume")[0]
        self.assertEqual(create[:3], ["docker", "volume", "create"])
        self.assertEqual(create[-1], vol)
        self.assertIn(f"gmshield-ci.run={RUN_ID}", create)
        self.assertIn(f"{vol}:/data:rw", self.docker_cmds("run")[0])
        self.assertIn(["docker", "volume", "rm", "-f", vol], self.cmds)
        self.assertFalse((run.work / "mounts").exists())

    def test_staging_volume_failure(self):
        self.capture_rc["docker volume create"] = 1
        run = self.run_for('[service]\nport = 80\n[deploy]\nmounts = [{ name = "uploads", target = "/data" }]\n')
        outcome, _, _, detail = stages.dast_staging(run)
        self.assertEqual((outcome, detail), ("error", "cannot create the staging volume for mount 'uploads'"))
        self.assertEqual(self.docker_cmds("run"), [])

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
        self.assertIn(f"gmshield-ci.run={RUN_ID}", build)
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


class MainFlowTest(unittest.TestCase):
    """The kept previous container: discarded once the release stands, restored after a failed DAST."""
    def flow(self, dast_status: str, rollback_on_fail: bool = True):
        calls = []
        run = types.SimpleNamespace(
            records=[], notes=[], deployed=False, contract=types.SimpleNamespace(has_dockerfile=True, self_update=False),
            repo=types.SimpleNamespace(name="GMshield-x"), dir=Path("/nonexistent"),
            s=types.SimpleNamespace(state_dir=Path("/nonexistent"),
                                    gates={"dast_main": {"rollback_on_fail": rollback_on_fail}}))

        def execute(run, key, title, gate, fn, *a):
            if key == "deploy":
                run.deployed = True
            r = stages.Record(key, title, gate, status=dast_status if key == "dast_prod" else "passed")
            run.records.append(r)
            return [r]
        with mock.patch.object(pipeline, "_read", lambda *a: {}), \
                mock.patch.object(pipeline.stages, "execute", execute), \
                mock.patch.object(pipeline.stages, "rollback", lambda run, log: calls.append("rollback") or "rolled"), \
                mock.patch.object(pipeline.stages, "discard_previous", lambda run: calls.append("discard")), \
                mock.patch.object(pipeline.stages, "mark_prod", lambda run: None):
            pipeline.main_flow(run)
        return calls

    def test_passed_dast_discards_the_previous_container(self):
        self.assertEqual(self.flow("passed"), ["discard"])

    def test_failed_dast_restores_it(self):
        self.assertEqual(self.flow("failed"), ["rollback"])

    def test_failed_dast_without_rollback_discards_it(self):
        self.assertEqual(self.flow("failed", rollback_on_fail=False), ["discard"])


class CleanupTest(unittest.TestCase):
    def test_cleanup_label_removes_containers_networks_volumes_and_stage_images(self):
        ran = []
        listed = {"ps": "c1", "network": "n1", "volume": "v1 v2", "image": "i1 i1"}
        with mock.patch.object(dockerops, "capture", lambda cmd, timeout=120: (0, listed[cmd[1]])), \
                mock.patch.object(dockerops, "sh", lambda cmd, *a, **k: ran.append(cmd) or 0):
            dockerops.cleanup_label("gmshield-ci.run=r")
        self.assertEqual(ran, [["docker", "rm", "-f", "-v", "c1"], ["docker", "network", "rm", "n1"],
                               ["docker", "volume", "rm", "-f", "v1", "v2"], ["docker", "image", "rm", "-f", "i1"]])

    def test_nothing_listed_nothing_removed(self):
        ran = []
        with mock.patch.object(dockerops, "capture", lambda cmd, timeout=120: (0, "")), \
                mock.patch.object(dockerops, "sh", lambda cmd, *a, **k: ran.append(cmd) or 0):
            dockerops.cleanup_label("gmshield-ci.run=r")
        self.assertEqual(ran, [])


class SonarTest(unittest.TestCase):
    """sonar.analyze and jdk_home with Docker and the SonarQube API replaced."""
    DIGEST = "4"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.sh_calls = []
        self.copy_ok = True
        self.scanner_rc = 0
        self.scanner_log = "INFO done\n"
        for p in (mock.patch.object(sonar, "sh", self.fake_sh),
                  mock.patch.object(sonar.Session, "ensure_up", classmethod(lambda cls, *a, **k: None)),
                  mock.patch.object(sonar, "token", lambda: "tok"),
                  mock.patch.object(sonar, "api", self.fake_api),
                  mock.patch.object(sonar.time, "sleep", lambda s: None)):
            p.start()
            self.addCleanup(p.stop)

    def fake_sh(self, cmd, log=None, timeout=600, env=None, cwd=None):
        self.sh_calls.append(cmd)
        if cmd[:2] == ["docker", "cp"] and self.copy_ok:
            dest = Path(cmd[3])
            dest.mkdir(parents=True)
            (dest / "release").write_text('JAVA_VERSION="27"')
        return 0

    def fake_api(self, method, path, params=None, auth=None, timeout=30):
        return 200, {"/api/ce/task": {"task": {"status": "SUCCESS", "analysisId": "a1"}},
                     "/api/qualitygates/project_status": {"projectStatus": {"status": "OK", "conditions": []}},
                     }.get(path, {})

    def run_obj(self):
        s = settings(self.tmp / "home", sonar=60)
        run = types.SimpleNamespace(s=s, id=RUN_ID, sha=SHA, dir=self.tmp / "art", work=self.tmp / "work",
                                    src=self.tmp / "src", repo=types.SimpleNamespace(name="GMshield-backend"))
        run.dir.mkdir()
        run.src.mkdir()
        test = self

        class Docker(FakeDocker):
            def run(self, name, image, args, **kw):
                self.calls.append((name, image, args, kw))
                kw["log"].write_text(test.scanner_log)
                if test.scanner_rc == 0:
                    (run.src / ".scannerwork").mkdir(exist_ok=True)
                    (run.src / ".scannerwork" / "report-task.txt").write_text("ceTaskId=t1\ndashboardUrl=x\n")
                return test.scanner_rc
        run.docker = Docker()
        return run

    def reports(self, run, classes=True, jars=("a.jar",)):
        r = run.dir / "unit-tests"
        if classes:
            (r / "classes").mkdir(parents=True)
        if jars is not None:
            (r / "libraries").mkdir(parents=True)
            for j in jars:
                (r / "libraries" / j).write_text("jar")

    def scan(self, run):
        outcome, metrics, files, detail = sonar.analyze(run)
        name, image, args, kw = run.docker.calls[0]
        return outcome, metrics, args, kw

    def test_jdk_home_and_libraries_passed(self):
        run = self.run_obj()
        self.reports(run)
        outcome, m, args, kw = self.scan(run)
        self.assertEqual(outcome, "ok")
        jdk = run.s.cache / "jdk" / self.DIGEST
        self.assertIn("-Dsonar.java.binaries=.gmshield-reports/classes", args)
        self.assertIn(f"-Dsonar.java.jdkHome={sonar.JDK_MOUNT}", args)
        self.assertIn((jdk, sonar.JDK_MOUNT, "ro"), kw["mounts"])
        self.assertIn("-Dsonar.java.libraries=.gmshield-reports/libraries/*.jar", args)
        self.assertIn("-Dsonar.java.test.libraries=.gmshield-reports/classes,.gmshield-reports/libraries/*.jar", args)
        self.assertEqual(m["warnings"], [])
        self.assertTrue((jdk / "release").is_file())
        self.assertIn(["docker", "rm", "-f", "-v", f"gmshield-ci-{RUN_ID}-jdk"], self.sh_calls)

    def test_jdk_cache_is_reused(self):
        run = self.run_obj()
        jdk = run.s.cache / "jdk" / self.DIGEST
        jdk.mkdir(parents=True)
        (jdk / "release").write_text("x")
        self.assertEqual(sonar.jdk_home(run, run.dir / "l.log"), jdk)
        self.assertEqual(self.sh_calls, [])

    def test_incomplete_jdk_cache_is_replaced(self):
        run = self.run_obj()
        jdk = run.s.cache / "jdk" / self.DIGEST
        jdk.mkdir(parents=True)
        (jdk / "stale").write_text("x")                      # no release file: an interrupted copy
        self.assertEqual(sonar.jdk_home(run, run.dir / "l.log"), jdk)
        self.assertTrue((jdk / "release").is_file())
        self.assertFalse((jdk / "stale").exists())

    def test_failed_copy_warns_without_gate_change(self):
        self.copy_ok = False
        run = self.run_obj()
        self.reports(run)
        outcome, m, args, _ = self.scan(run)
        self.assertEqual((outcome, m["status"]), ("ok", "OK"))
        self.assertFalse(any("jdkHome" in a for a in args))
        self.assertTrue(any("could not be prepared" in w for w in m["warnings"]))
        self.assertFalse((run.s.cache / "jdk" / self.DIGEST).exists())
        self.assertFalse((run.s.cache / "jdk" / f"{self.DIGEST}.partial").exists())

    def test_no_libraries_without_jars(self):
        for jars in ((), None):
            with self.subTest(jars=jars):
                shutil.rmtree(self.tmp, ignore_errors=True)
                self.tmp.mkdir()
                run = self.run_obj()
                self.reports(run, jars=jars)
                _, _, args, _ = self.scan(run)
                self.assertFalse(any("libraries" in a for a in args))

    def test_no_java_no_jdk(self):
        run = self.run_obj()
        _, m, args, kw = self.scan(run)
        self.assertFalse(any(a.startswith("-Dsonar.java") for a in args))
        self.assertEqual(self.sh_calls, [])
        self.assertEqual(m["warnings"], [])

    def test_unresolved_types_warn(self):
        self.scanner_log = "WARN Unresolved imports/types have been detected during analysis.\n"
        run = self.run_obj()
        self.reports(run)
        outcome, m, _, _ = self.scan(run)
        self.assertEqual((outcome, m["status"]), ("ok", "OK"))
        self.assertTrue(any("Unresolved imports/types" in w for w in m["warnings"]))

    def test_warnings_kept_when_the_scanner_fails(self):
        self.copy_ok = False
        self.scanner_rc = 2
        self.scanner_log = "WARN Unresolved imports/types\n"
        run = self.run_obj()
        self.reports(run)
        outcome, m, _, _ = self.scan(run)
        self.assertEqual(outcome, "error")
        self.assertEqual(len(m["warnings"]), 2)


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
