"""Tests for deploy/data-credentials.sh in a temporary GMSHIELD_HOME and GMSHIELD_STACK.

Run: python3 -m unittest tests.test_data_credentials -v
"""
import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "data-credentials.sh"
SECRET_KEYS = {
    "stack/.env": ["POSTGRES_PASSWORD", "REDIS_PROBE_PASSWORD", "QDRANT_API_KEY"],
    "gmshield-ci/secrets/backend.env": ["GMSHIELD_DB_PASSWORD", "GMSHIELD_REDIS_PASSWORD"],
    "gmshield-ci/secrets/worker.env": ["GMSHIELD_REDIS_PASSWORD", "GMSHIELD_QDRANT_API_KEY"],
}


def env_file(path: Path) -> dict:
    return dict(l.split("=", 1) for l in path.read_text().splitlines() if "=" in l)


class DataCredentialsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args):
        env = {**os.environ, "GMSHIELD_HOME": str(self.base / "gmshield-ci"),
               "GMSHIELD_STACK": str(self.base / "stack"), "LC_ALL": "C"}
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)

    def ok(self):
        res = self.run_script()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return res

    def digests(self) -> dict:
        return {str(f.relative_to(self.base)): hashlib.sha256(f.read_bytes()).hexdigest()
                for f in sorted(self.base.rglob("*")) if f.is_file()}

    def test_every_secret_is_random_32_bytes_mode_600_and_never_printed(self):
        res = self.ok()
        seen = set()
        for rel, keys in SECRET_KEYS.items():
            f = self.base / rel
            self.assertEqual(f.stat().st_mode & 0o777, 0o600, rel)
            values = env_file(f)
            for k in keys:
                self.assertRegex(values[k], r"^[0-9a-f]{64}$", k)
                self.assertNotIn(values[k], res.stdout + res.stderr)
                seen.add(values[k])
        # one credential per client: only the Qdrant key is shared (Qdrant and the worker)
        self.assertEqual(len(seen), 6)
        self.assertEqual(env_file(self.base / "stack/.env")["QDRANT_API_KEY"],
                         env_file(self.base / "gmshield-ci/secrets/worker.env")["GMSHIELD_QDRANT_API_KEY"])
        self.assertEqual((self.base / "gmshield-ci/secrets").stat().st_mode & 0o777, 0o700)

    def test_backend_settings_use_its_own_accounts_and_verified_tls(self):
        self.ok()
        b = env_file(self.base / "gmshield-ci/secrets/backend.env")
        self.assertEqual(b["GMSHIELD_DB_URL"], "jdbc:postgresql://postgres:5432/gmshield"
                                               "?sslmode=verify-full&sslrootcert=/run/gmshield/certs/ca.crt")
        self.assertEqual(b["GMSHIELD_DB_USER"], "gmshield_backend")
        self.assertEqual(b["GMSHIELD_REDIS_USERNAME"], "backend")
        self.assertEqual(env_file(self.base / "gmshield-ci/secrets/worker.env")["GMSHIELD_REDIS_USERNAME"], "worker")
        self.assertEqual(env_file(self.base / "gmshield-ci/secrets/frontend.env")["GMSHIELD_BACKEND_URL"],
                         "http://gmshield-backend:8080")

    def test_redis_accounts_hold_hashes_and_least_privilege(self):
        self.ok()
        acl = (self.base / "stack/redis-users.acl").read_text()
        self.assertEqual((self.base / "stack/redis-users.acl").stat().st_mode & 0o777, 0o600)
        users = {l.split()[1]: l for l in acl.splitlines()}
        self.assertEqual(sorted(users), ["backend", "default", "probe", "worker"])
        self.assertIn(" off ", users["default"] + " ")
        for name, (rel, key) in {"backend": ("gmshield-ci/secrets/backend.env", "GMSHIELD_REDIS_PASSWORD"),
                                 "worker": ("gmshield-ci/secrets/worker.env", "GMSHIELD_REDIS_PASSWORD"),
                                 "probe": ("stack/.env", "REDIS_PROBE_PASSWORD")}.items():
            pw = env_file(self.base / rel)[key]
            self.assertIn("#" + hashlib.sha256(pw.encode()).hexdigest(), users[name])
            self.assertNotIn(pw, acl)
        self.assertIn("~gmshield:*", users["backend"])
        worker = users["worker"].split()
        self.assertEqual([w for w in worker if w.startswith("~")],
                         ["~gmshield:work:interactive", "~gmshield:work:ingestion"])
        self.assertEqual([w for w in worker if w[0] in "+-"],
                         ["-@all", "+auth", "+hello", "+ping", "+xreadgroup", "+xack", "+xautoclaim", "+xclaim",
                          "+xpending"])
        self.assertEqual([w for w in users["probe"].split() if w[0] in "+-"], ["-@all", "+ping"])

    def test_rerun_keeps_every_value_and_says_already_done(self):
        self.ok()
        before = self.digests()
        res = self.ok()
        self.assertEqual(self.digests(), before)
        self.assertNotIn("generated", res.stdout)
        self.assertNotIn("written", res.stdout)
        self.assertGreaterEqual(res.stdout.count("already done"), 17)

    def test_an_existing_secret_is_kept(self):
        stack = self.base / "stack"
        stack.mkdir()
        (stack / ".env").write_text("POSTGRES_PASSWORD=kept-from-before\n")
        self.ok()
        values = env_file(stack / ".env")
        self.assertEqual(values["POSTGRES_PASSWORD"], "kept-from-before")
        self.assertRegex(values["REDIS_PROBE_PASSWORD"], r"^[0-9a-f]{64}$")

    def test_a_qdrant_key_that_differs_between_server_and_worker_is_refused(self):
        self.ok()
        w = self.base / "gmshield-ci/secrets/worker.env"
        w.write_text(re.sub(r"GMSHIELD_QDRANT_API_KEY=.*", "GMSHIELD_QDRANT_API_KEY=other", w.read_text()))
        res = self.run_script()
        self.assertEqual(res.returncode, 1)
        self.assertIn("differs", res.stderr)
        self.assertNotIn("other", res.stdout + res.stderr)

    def test_usage(self):
        self.assertEqual(self.run_script("--force").returncode, 2)


if __name__ == "__main__":
    unittest.main()
