"""Tests for deploy/certs.sh with the real openssl in a temporary GMSHIELD_HOME.

Run: python3 -m unittest tests.test_certs -v
"""
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "certs.sh"
SERVERS = ("postgres", "redis", "qdrant")
CLIENTS = ("backend", "worker")


def openssl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *args], capture_output=True, text=True)


class CertsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "gmshield-ci"
        self.ca, self.certs = self.home / "ca", self.home / "certs"

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args):
        env = {**os.environ, "GMSHIELD_HOME": str(self.home), "LC_ALL": "C"}
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=120)

    def issue(self, *extra):
        res = self.run_script("issue", *extra)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return res

    def digests(self) -> dict:
        return {str(f.relative_to(self.home)): hashlib.sha256(f.read_bytes()).hexdigest()
                for f in sorted(self.home.rglob("*")) if f.is_file()}

    def mode(self, p: Path) -> int:
        return p.stat().st_mode & 0o777

    def test_issue_creates_the_authority_and_one_folder_per_service(self):
        self.issue()
        self.assertEqual(self.mode(self.ca), 0o700)
        self.assertEqual(self.mode(self.ca / "ca.key"), 0o600)
        for svc in SERVERS:
            d = self.certs / svc
            self.assertEqual(sorted(f.name for f in d.iterdir()), ["ca.crt", "tls.crt", "tls.key"])
            self.assertEqual(self.mode(d / "tls.key"), 0o600)
            self.assertEqual(self.mode(d / "tls.crt"), 0o644)
            self.assertEqual(self.mode(d / "ca.crt"), 0o644)
            # the chain and the host name verify; another name does not
            res = openssl("verify", "-CAfile", str(self.ca / "ca.crt"), "-verify_hostname", svc, str(d / "tls.crt"))
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            res = openssl("verify", "-CAfile", str(self.ca / "ca.crt"), "-verify_hostname", "elsewhere", str(d / "tls.crt"))
            self.assertNotEqual(res.returncode, 0)
            days = openssl("x509", "-in", str(d / "tls.crt"), "-noout", "-checkend", str(364 * 86400))
            self.assertEqual(days.returncode, 0)
            days = openssl("x509", "-in", str(d / "tls.crt"), "-noout", "-checkend", str(366 * 86400))
            self.assertNotEqual(days.returncode, 0)                       # valid 365 days
        for svc in CLIENTS:
            self.assertEqual(sorted(f.name for f in (self.certs / svc).iterdir()), ["ca.crt"])
            self.assertEqual(self.mode(self.certs / svc), 0o755)
        # the authority's key is in no service folder
        for f in self.certs.rglob("*"):
            if f.is_file():
                self.assertNotEqual(f.read_bytes(), (self.ca / "ca.key").read_bytes())
        self.assertNotIn("PRIVATE KEY", self.issue().stdout)

    def test_rerun_keeps_everything_and_says_already_done(self):
        self.issue()
        before = self.digests()
        res = self.issue()
        self.assertEqual(res.stdout.count("already done"), 1 + len(SERVERS) + len(CLIENTS))
        self.assertEqual(self.digests(), before)

    def test_renew_replaces_the_leaves_only(self):
        self.issue()
        before = self.digests()
        self.issue("--renew")
        after = self.digests()
        self.assertEqual(after["ca/ca.key"], before["ca/ca.key"])
        self.assertEqual(after["ca/ca.crt"], before["ca/ca.crt"])
        for svc in SERVERS:
            self.assertNotEqual(after[f"certs/{svc}/tls.key"], before[f"certs/{svc}/tls.key"])
            self.assertNotEqual(after[f"certs/{svc}/tls.crt"], before[f"certs/{svc}/tls.crt"])
        for svc in CLIENTS:
            self.assertEqual(after[f"certs/{svc}/ca.crt"], before[f"certs/{svc}/ca.crt"])

    def test_a_missing_or_foreign_leaf_is_issued_again(self):
        self.issue()
        (self.certs / "redis" / "tls.key").unlink()
        res = self.issue()
        self.assertIn("issued", res.stdout)
        self.assertTrue((self.certs / "redis" / "tls.key").exists())

    def test_check_is_quiet_when_every_certificate_is_far_from_expiry(self):
        self.issue()
        res = self.run_script("check")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn("WARNING", res.stdout)
        self.assertIn("ok: 4 certificates", res.stdout)

    def test_check_warns_about_a_leaf_with_20_days_left_and_still_exits_0(self):
        self.issue()
        d = self.certs / "qdrant"
        work = Path(self.tmp.name)
        (work / "ext").write_text("subjectAltName=DNS:qdrant\n")
        res = openssl("req", "-new", "-key", str(d / "tls.key"), "-subj", "/CN=qdrant", "-out", str(work / "csr"))
        self.assertEqual(res.returncode, 0, res.stderr)
        res = openssl("x509", "-req", "-in", str(work / "csr"), "-CA", str(self.ca / "ca.crt"), "-CAkey",
                      str(self.ca / "ca.key"), "-set_serial", "7", "-days", "20", "-extfile", str(work / "ext"),
                      "-out", str(d / "tls.crt"))
        self.assertEqual(res.returncode, 0, res.stderr)
        res = self.run_script("check")
        self.assertEqual(res.returncode, 0)
        self.assertIn(f"WARNING: {d / 'tls.crt'} expires on", res.stdout)
        self.assertIn("issue --renew", res.stdout)
        self.assertEqual(res.stdout.count("WARNING"), 1)

    def test_check_without_certificates_warns_and_exits_0(self):
        res = self.run_script("check")
        self.assertEqual(res.returncode, 0)
        self.assertIn("WARNING: no certificates", res.stdout)

    def test_half_an_authority_is_refused(self):
        self.ca.mkdir(parents=True)
        (self.ca / "ca.crt").write_text("left over\n")
        res = self.run_script("issue")
        self.assertEqual(res.returncode, 1)
        self.assertIn("half an authority", res.stderr)

    def test_usage(self):
        for args in ([], ["renew"], ["issue", "--now"], ["check", "x"]):
            self.assertEqual(self.run_script(*args).returncode, 2, args)


if __name__ == "__main__":
    unittest.main()
