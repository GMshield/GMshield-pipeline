"""Tests for deploy/secure-ollama.sh against a fake server (tests/fixtures/secure-ollama/stub.py).

The system tools are PATH stubs that log their arguments and keep a small state; every file the script
touches lives under a temporary GMSHIELD_ROOT. Run: python3 -m unittest tests.test_secure_ollama -v
"""
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "secure-ollama.sh"
STUB = Path(__file__).resolve().parent / "fixtures" / "secure-ollama" / "stub.py"
TOOLS = ["id", "systemctl", "ufw", "ollama", "ss", "ip", "docker"]
STEPS = 6
OLD_RULE = "11434/tcp                  ALLOW IN    172.16.0.0/12              # docker containers -> ollama"
DENY_RULE = "11434/tcp                  DENY IN     Anywhere                   # ollama closed to LAN"
DROPINS = "etc/systemd/system/ollama.service.d"
MUTATING = ("restart", "rm", "insert", "--force", "daemon-reload")


class SecureOllamaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root, self.bin = base / "root", base / "bin"
        self.state, self.log = base / "state.json", base / "calls.log"
        self.bin.mkdir()
        for tool in TOOLS:
            (self.bin / tool).symlink_to(STUB)
        d = self.root / DROPINS
        d.mkdir(parents=True)
        (d / "network.conf").write_text('[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0:11434"\n')
        (d / "rag-tuning.conf").write_text('[Service]\nEnvironment="OLLAMA_MAX_LOADED_MODELS=2"\n')
        (self.root / "usr/local/bin").mkdir(parents=True)
        (self.root / "usr/local/bin/ai-healthcheck").write_text("#!/bin/sh\nAPI=http://127.0.0.1:11434\n")
        self.state.write_text(json.dumps({
            "network": True, "listening": ["*:11434"], "restarts": 0,
            "models": ["embeddinggemma:300m", "qwen3.5:4b"],
            "rules": ["22/tcp                     ALLOW IN    Anywhere", OLD_RULE, DENY_RULE]}))
        self.log.touch()

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args, **env):
        e = {"PATH": f"{self.bin}:/usr/bin:/bin", "GMSHIELD_ROOT": str(self.root), "STUB_STATE": str(self.state),
             "STUB_LOG": str(self.log), "LC_ALL": "C", **env}
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=120)

    def st(self) -> dict:
        return json.loads(self.state.read_text())

    def snapshot(self) -> dict:
        files = {str(f.relative_to(self.root)): hashlib.sha256(f.read_bytes()).hexdigest()
                 for f in sorted(self.root.rglob("*")) if f.is_file()}
        return {"files": files, "state": self.st()}

    def mutating_calls(self) -> list[str]:
        return [c for c in self.log.read_text().splitlines() if any(w in c.split() for w in MUTATING)]

    def apply_ok(self):
        res = self.run_script("apply")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return res

    # ---------- plan and refusals ----------
    def test_plan_changes_nothing_and_lists_every_step(self):
        before = self.snapshot()
        res = self.run_script("plan")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("nothing is changed", res.stdout)
        self.assertEqual(res.stdout.count("[  --]"), STEPS)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.mutating_calls(), [])

    def test_apply_refuses_before_the_stack_created_the_network(self):
        st = self.st(); st["network"] = False; self.state.write_text(json.dumps(st))
        before = self.snapshot()
        res = self.run_script("apply")
        self.assertEqual(res.returncode, 1)
        self.assertIn("deploy/stack.sh up first", res.stderr)
        self.assertIn("FAILED at step 0", res.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_apply_refuses_without_root(self):
        before = self.snapshot()
        res = self.run_script("apply", STUB_UID="1000")
        self.assertEqual(res.returncode, 1)
        self.assertIn("not root", res.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_usage(self):
        self.assertEqual(self.run_script().returncode, 2)
        self.assertEqual(self.run_script("apply", "--now").returncode, 2)

    # ---------- apply ----------
    def test_apply_narrows_ollama(self):
        res = self.apply_ok()
        st = self.st()
        self.assertEqual(st["models"], ["embeddinggemma:300m"])
        self.assertEqual(st["listening"], ["172.30.5.1:11434"])
        self.assertEqual(st["restarts"], 1)
        # the new rule comes first, so the existing deny below it never wins; the old allow is gone
        self.assertTrue(st["rules"][0].startswith("172.30.5.1 11434/tcp on gmshield-model  ALLOW IN    172.30.5.0/24"))
        self.assertNotIn(OLD_RULE, st["rules"])
        self.assertIn(DENY_RULE, st["rules"])
        dropin = (self.root / DROPINS / "zz-gmshield.conf").read_text()
        self.assertIn('Environment="OLLAMA_HOST=172.30.5.1:11434"', dropin)
        self.assertIn('Environment="OLLAMA_MAX_LOADED_MODELS=1"', dropin)
        self.assertIn("After=docker.service", dropin)
        self.assertIn("$$(seq 1 90)", dropin)          # systemd turns $$ into $
        self.assertFalse((self.root / DROPINS / "network.conf").exists())
        self.assertTrue((self.root / "var/lib/gmshield/secure-ollama/network.conf.before-gmshield").exists())
        self.assertTrue((self.root / DROPINS / "rag-tuning.conf").exists())
        health = (self.root / "usr/local/bin/ai-healthcheck").read_text()
        self.assertIn("API=http://172.30.5.1:11434", health)
        self.assertNotIn("6333", health)
        self.assertIn("API=http://127.0.0.1:11434",
                      (self.root / "var/lib/gmshield/secure-ollama/ai-healthcheck.before-gmshield").read_text())
        self.assertEqual(res.stdout.count("already done"), 0)
        self.assertIn("DONE", res.stdout)

    def test_rerun_changes_nothing(self):
        self.apply_ok()
        self.log.write_text("")
        before = self.snapshot()
        res = self.apply_ok()
        self.assertEqual(res.stdout.count("already done"), STEPS)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.mutating_calls(), [])

    def test_a_failure_names_the_step_and_a_rerun_resumes(self):
        res = self.run_script("apply", STUB_FAIL="ufw")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAILED at step 2", res.stderr)
        self.assertEqual(self.st()["models"], ["embeddinggemma:300m"])      # step 1 stays done
        res = self.apply_ok()
        self.assertEqual(res.stdout.count("already done"), 1)
        self.assertEqual(self.st()["listening"], ["172.30.5.1:11434"])

    def test_an_unreadable_firewall_never_counts_as_done(self):
        res = self.run_script("plan", STUB_UID="1000")       # ufw status needs root
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("[  --] 2 Allow", res.stdout)
        self.assertIn("[  --] 3 Remove the ufw rule", res.stdout)

    def test_status_reports_every_step(self):
        self.apply_ok()
        res = self.run_script("status")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.count("[done]"), STEPS)
        self.assertIn("Ollama listens on: 172.30.5.1:11434", res.stdout)
        self.assertIn("OLLAMA_MAX_LOADED_MODELS=1", res.stdout)
        self.assertIn("Models: embeddinggemma:300m", res.stdout)

    def test_bash_syntax(self):
        for script in sorted((REPO / "deploy").glob("*.sh")) + sorted((REPO / "infra").rglob("*.sh")) + \
                sorted((REPO / "tests").glob("*.sh")):
            res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"{script}: {res.stderr}")


if __name__ == "__main__":
    unittest.main()
