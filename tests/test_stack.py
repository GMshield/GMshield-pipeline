"""Tests for deploy/stack.sh against a fake docker (tests/fixtures/stack/stub.py), in a temporary
GMSHIELD_HOME and GMSHIELD_STACK, with the repository's own infra/. Run: python3 -m unittest tests.test_stack -v
"""
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "stack.sh"
STUB = Path(__file__).resolve().parent / "fixtures" / "stack" / "stub.py"
DB_PW = "a" * 64
ENV = "POSTGRES_PASSWORD=p1\nREDIS_PROBE_PASSWORD=p2\nQDRANT_API_KEY=p3\n"
ACL = "user default off\nuser probe on #abc -@all +ping\n"
OLD_COMPOSE = "name: rpg\nservices: {}\n"
COPIED = ["compose.yaml", "postgres/start.sh", "postgres/pg_hba.conf", "postgres/pg_ident.conf", "redis/start.sh"]


class StackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.home, self.stack, self.bin = base / "ci", base / "stack", base / "bin"
        self.log = base / "calls.log"
        self.bin.mkdir()
        (self.bin / "docker").symlink_to(STUB)
        for svc in ("postgres", "redis", "qdrant"):
            d = self.home / "certs" / svc
            d.mkdir(parents=True)
            for f in ("tls.crt", "tls.key", "ca.crt"):
                (d / f).write_text(f"{svc} {f}\n")
        (self.home / "secrets").mkdir()
        (self.home / "secrets" / "backend.env").write_text(f"GMSHIELD_DB_PASSWORD={DB_PW}\n")
        self.stack.mkdir()
        (self.stack / ".env").write_text(ENV)
        (self.stack / "redis-users.acl").write_text(ACL)
        (self.stack / "compose.yaml").write_text(OLD_COMPOSE)
        self.log.touch()

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args, **env):
        e = {"PATH": f"{self.bin}:/usr/bin:/bin", "GMSHIELD_HOME": str(self.home), "GMSHIELD_STACK": str(self.stack),
             "STUB_LOG": str(self.log), "GMSHIELD_STACK_WAIT": "6", "LC_ALL": "C", **env}
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=60)

    def up(self, **env):
        res = self.run_script("up", **env)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return res

    def snapshot(self) -> dict:
        return {str(f.relative_to(self.stack)): hashlib.sha256(f.read_bytes()).hexdigest()
                for f in sorted(self.stack.rglob("*")) if f.is_file()}

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    def recreated(self) -> list[str]:
        return [c for c in self.calls() if "--force-recreate" in c]

    def psql_input(self) -> str:
        p = Path(str(self.log) + ".psql")
        return p.read_text() if p.exists() else ""

    # ---------- preconditions ----------
    def test_each_missing_precondition_is_refused_and_changes_nothing(self):
        cases = {
            "certificate": lambda: (self.home / "certs" / "redis" / "tls.key").unlink(),
            "stack secret": lambda: (self.stack / ".env").write_text("POSTGRES_PASSWORD=p1\nQDRANT_API_KEY=p3\n"),
            "account list": lambda: (self.stack / "redis-users.acl").unlink(),
            "backend password": lambda: (self.home / "secrets" / "backend.env").write_text("GMSHIELD_DB_USER=x\n"),
        }
        for name, breaks in cases.items():
            with self.subTest(name):
                self.tmp.cleanup()
                self.setUp()                                 # a fresh server for each case
                breaks()
                before = self.snapshot()
                res = self.run_script("up")
                self.assertEqual(res.returncode, 1, res.stdout)
                self.assertIn("refused:", res.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertFalse([c for c in self.calls() if " up " in f" {c} "])

    def test_a_missing_qdrant_volume_is_refused(self):
        before = self.snapshot()
        res = self.run_script("up", STUB_NO_QDRANT_VOLUME="1")
        self.assertEqual(res.returncode, 1)
        self.assertIn("refused: the external volume qdrant_data does not exist", res.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_a_password_with_other_characters_is_refused_before_psql(self):
        (self.home / "secrets" / "backend.env").write_text("GMSHIELD_DB_PASSWORD=abc'; DROP ROLE x; --\n")
        before = self.snapshot()
        res = self.run_script("up")
        self.assertEqual(res.returncode, 1)
        self.assertIn("refused: GMSHIELD_DB_PASSWORD", res.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.psql_input(), "")
        self.assertNotIn("DROP", res.stdout + res.stderr)

    # ---------- up ----------
    def test_up_copies_infra_and_keeps_the_secrets_byte_for_byte(self):
        self.up()
        self.assertEqual((self.stack / ".env").read_text(), ENV)
        self.assertEqual((self.stack / "redis-users.acl").read_text(), ACL)
        for f in COPIED:
            self.assertEqual((self.stack / f).read_bytes(), (REPO / "infra" / f).read_bytes(), f)
        self.assertEqual((self.stack / "compose.yaml.before-1-6").read_text(), OLD_COMPOSE)
        self.assertTrue([c for c in self.calls() if c.startswith("compose ") and " up -d" in c])

    def test_the_old_compose_file_is_saved_once(self):
        self.up()
        self.up()
        self.assertEqual((self.stack / "compose.yaml.before-1-6").read_text(), OLD_COMPOSE)
        self.assertEqual(sorted(f.name for f in self.stack.glob("compose.yaml*")), ["compose.yaml", "compose.yaml.before-1-6"])

    def test_the_password_reaches_psql_on_stdin_only_and_nothing_is_logged(self):
        res = self.up()
        sql = self.psql_input()
        self.assertIn(f"PASSWORD '{DB_PW}'", sql)
        self.assertLess(sql.index("SET log_min_error_statement = panic;"), sql.index("ALTER ROLE"))
        self.assertLess(sql.index("SET log_statement = 'none';"), sql.index("ALTER ROLE"))
        self.assertNotIn(DB_PW, self.log.read_text())       # never on a command line
        self.assertNotIn(DB_PW, res.stdout + res.stderr)

    def test_a_changed_certificate_or_account_list_recreates_that_service_only(self):
        self.up()                                            # no stamps yet: every service is recreated once
        self.assertEqual(len(self.recreated()), 1)
        self.assertTrue(self.recreated()[0].endswith("--force-recreate postgres redis qdrant"))
        self.log.write_text("")
        self.up()
        self.assertEqual(self.recreated(), [])               # nothing changed
        (self.home / "certs" / "redis" / "tls.crt").write_text("renewed\n")
        self.up()
        self.assertEqual(len(self.recreated()), 1)
        self.assertTrue(self.recreated()[0].endswith("--force-recreate redis"))
        self.log.write_text("")
        (self.stack / "redis-users.acl").write_text(ACL + "user worker on #def -@all\n")
        (self.home / "certs" / "postgres" / "tls.key").write_text("renewed\n")
        self.up()
        self.assertTrue(self.recreated()[0].endswith("--force-recreate postgres redis"))

    def test_a_failed_up_writes_no_stamp(self):
        self.up()
        (self.home / "certs" / "qdrant" / "tls.crt").write_text("renewed\n")
        (self.stack / ".env").write_text("POSTGRES_PASSWORD=p1\n")      # the next up is refused
        self.assertEqual(self.run_script("up").returncode, 1)
        (self.stack / ".env").write_text(ENV)
        self.log.write_text("")
        self.up()
        self.assertTrue(self.recreated()[0].endswith("--force-recreate qdrant"))

    def test_the_old_network_goes_only_when_no_container_uses_it(self):
        self.up(STUB_OLD_NETWORK="1", STUB_OLD_NETWORK_USED="1")
        self.assertNotIn("network rm rpg_default", self.calls())
        self.up(STUB_OLD_NETWORK="1")
        self.assertIn("network rm rpg_default", self.calls())

    def test_usage(self):
        self.assertEqual(self.run_script().returncode, 2)
        self.assertEqual(self.run_script("down").returncode, 2)


if __name__ == "__main__":
    unittest.main()
