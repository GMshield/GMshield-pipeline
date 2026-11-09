"""Unit tests for report parsing, quality gates and the repo contract. Run: python3 -m unittest -v"""
import tempfile
import tomllib
import unittest
from pathlib import Path

from gmshield_ci import gates
from gmshield_ci.config import RUNNER_DIR, load_contract

FIX = Path(__file__).parent / "fixtures"
GATES = tomllib.loads((RUNNER_DIR / "gates.toml").read_text())


class ParserTest(unittest.TestCase):
    def test_gitleaks(self):
        m = gates.parse_gitleaks(FIX / "reports" / "gitleaks.json")
        self.assertEqual(m["findings"], 2)
        self.assertEqual(m["rules"]["aws-access-token"], 1)

    def test_semgrep_maps_old_and_new_severities(self):
        m = gates.parse_semgrep(FIX / "reports" / "semgrep.json")
        self.assertEqual((m["high"], m["medium"], m["low"], m["scan_errors"]), (2, 1, 1, 1))

    def test_trivy_counts_fixable_and_failed_misconfig(self):
        m = gates.parse_trivy(FIX / "reports" / "trivy.json")
        self.assertEqual(m["vuln"]["CRITICAL"], 1)
        self.assertEqual(m["vuln_fixable"]["CRITICAL"], 0)
        self.assertEqual(m["vuln_fixable"]["HIGH"], 1)
        self.assertEqual(m["misconfig"]["HIGH"], 1)

    def test_zap_counts_alert_types_and_ignores(self):
        m = gates.parse_zap(FIX / "reports" / "zap.json")
        self.assertEqual((m["high"], m["medium"], m["low"], m["info"]), (1, 1, 1, 1))
        m = gates.parse_zap(FIX / "reports" / "zap.json", {"40012"})
        self.assertEqual((m["high"], m["ignored"]), (0, 1))


class GateTest(unittest.TestCase):
    def judge(self, kind, metrics, outcome="ok"):
        return gates.judge(kind, outcome, metrics, GATES)

    def test_any_secret_blocks(self):
        self.assertEqual(self.judge("secrets", {"findings": 1})[0], "failed")
        self.assertEqual(self.judge("secrets", {"findings": 0})[0], "passed")

    def test_sast_high_blocks_medium_tolerated(self):
        self.assertEqual(self.judge("sast", {"high": 1, "medium": 0})[0], "failed")
        self.assertEqual(self.judge("sast", {"high": 0, "medium": 3})[0], "passed")

    def test_only_fixable_vulns_block(self):
        m = gates.parse_trivy(FIX / "reports" / "trivy.json")
        status, _, reasons = self.judge("sca", m)
        self.assertEqual(status, "failed")
        self.assertEqual(reasons, ["high 1 > 0"])           # the unfixable CRITICAL does not block

    def test_iac_high_blocks(self):
        m = gates.parse_trivy(FIX / "reports" / "trivy.json")
        self.assertEqual(self.judge("iac", m)[0], "failed")

    def test_dast_develop_high_blocks(self):
        m = gates.parse_zap(FIX / "reports" / "zap.json")
        self.assertEqual(self.judge("dast_develop", m)[0], "failed")

    def test_scanner_error_fails_closed(self):
        self.assertEqual(self.judge("sast", {"error": "boom"}, outcome="error")[0], "failed")

    def test_skipped_tests_pass_unless_required(self):
        self.assertEqual(self.judge("unit_tests", {}, outcome="skipped")[0], "skipped")
        strict = {**GATES, "unit_tests": {"required": True}}
        self.assertEqual(gates.judge("unit_tests", "skipped", {}, strict)[0], "failed")

    def test_failed_tests_block(self):
        self.assertEqual(self.judge("unit_tests", {"exit_code": 1})[0], "failed")

    def test_broken_image_build_blocks(self):
        self.assertEqual(self.judge("image", {"build_exit": 1})[0], "failed")

    def test_promotion(self):
        self.assertEqual(self.judge("promotion", {"promoted": False})[0], "failed")
        self.assertEqual(self.judge("promotion", {"promoted": True})[0], "passed")

    def test_sonar_gate_ok_passes(self):
        self.assertEqual(self.judge("sonar", {"status": "OK", "failed": []})[0], "passed")

    def test_sonar_gate_error_blocks_with_reasons(self):
        status, _, reasons = self.judge("sonar", {"status": "ERROR", "hotspots_to_review": 2,
                                                  "failed": ["new_security_hotspots_reviewed = 0.0 (fails when LT 100)"]})
        self.assertEqual(status, "failed")
        self.assertIn("2 security hotspot(s) await review in SonarQube", reasons)

    def test_sonar_without_verdict_fails_closed(self):
        self.assertEqual(self.judge("sonar", {"status": "NONE"})[0], "failed")

    def test_sonar_gate_defined_in_config(self):
        metrics = [c[0] for c in GATES["sonar"]["conditions"]]
        self.assertIn("new_security_hotspots_reviewed", metrics)
        self.assertIn("new_software_quality_security_rating", metrics)


class ContractTest(unittest.TestCase):
    def test_sample_app_contract(self):
        c = load_contract(FIX / "sample-app", "GMshield-sample")
        self.assertTrue(c.present and c.has_dockerfile and c.http)
        self.assertEqual((c.service, c.port, c.host_port), ("sample", 8080, 18080))
        self.assertEqual(c.dockerfile_stages, ["base", "test", "test-reports", "final"])

    def test_defaults_without_contract(self):
        with tempfile.TemporaryDirectory() as d:
            c = load_contract(Path(d), "GMshield-Worker")
        self.assertFalse(c.present or c.has_dockerfile or c.http)
        self.assertEqual(c.service, "worker")

    def test_pipeline_repo_self_updates(self):
        c = load_contract(RUNNER_DIR, "GMshield-pipeline")
        self.assertTrue(c.self_update)
        self.assertFalse(load_contract(FIX / "sample-app", "GMshield-sample").self_update)

    def test_dockerfile_outside_repo_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".gmshield").mkdir()
            (Path(d) / ".gmshield" / "pipeline.toml").write_text('[build]\ncontext = ".."\ndockerfile = "x"\n')
            c = load_contract(Path(d), "GMshield-x")
        self.assertFalse(c.has_dockerfile)


if __name__ == "__main__":
    unittest.main()
