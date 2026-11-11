"""Unit tests for report parsing, quality gates and the repo contract. Run: python3 -m unittest -v"""
import importlib.util
import json
import tempfile
import threading
import tomllib
import types
import unittest
from pathlib import Path

from gmshield_ci import gates, report, stages
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
        self.assertEqual((m["high"], m["medium"], m["low"], m["scan_errors"]), (2, 1, 1, 3))

    def test_semgrep_names_each_file_it_did_not_fully_scan(self):
        m = gates.parse_semgrep(FIX / "reports" / "semgrep.json")
        self.assertEqual(m["unscanned_files"], 3)
        self.assertEqual(m["warnings"], [
            "not fully scanned: file not named by Semgrep (parse error)",
            "not fully scanned: app/Modern.java (PartialParsing, lines 1, 16)",   # /src/ prefix removed
            "not fully scanned: app/Big.java (Timeout)"])

    def test_semgrep_clean_scan_has_no_warnings(self):
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "semgrep.json"
            report.write_text('{"results": [], "errors": []}')
            m = gates.parse_semgrep(report)
        self.assertEqual((m["scan_errors"], m["unscanned_files"], m["warnings"]), (0, 0, []))

    def test_semgrep_warning_list_is_capped(self):
        errors = [{"type": "Syntax error", "path": f"/src/f{i}.java", "spans": [{"start": {"line": 3}}]}
                  for i in range(40)]
        with tempfile.TemporaryDirectory() as d:
            report = Path(d) / "semgrep.json"
            report.write_text(json.dumps({"results": [], "errors": errors}))
            m = gates.parse_semgrep(report)
        self.assertEqual(m["unscanned_files"], 40)
        self.assertEqual(len(m["warnings"]), 16)
        self.assertEqual(m["warnings"][0], "not fully scanned: f0.java (Syntax error, line 3)")
        self.assertEqual(m["warnings"][-1], "... and 25 more file(s), see semgrep.json")

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

    def test_sast_scan_warnings_do_not_block(self):
        metrics = {"high": 0, "medium": 0, "low": 0, "unscanned_files": 1,
                   "warnings": ["not fully scanned: app/Modern.java (PartialParsing, lines 1, 16)"]}
        status, _, reasons = self.judge("sast", metrics)
        self.assertEqual((status, reasons), ("passed", []))

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


class WarningTest(unittest.TestCase):
    """A warning is shown in every report and never changes a stage's status."""
    WARNING = "not fully scanned: app/Modern.java (PartialParsing, lines 1, 16)"

    def fake_run(self):
        run = types.SimpleNamespace(records=[], lock=threading.Lock(), titles={}, logged=[],
                                    s=types.SimpleNamespace(gates=GATES))
        run.log = run.logged.append
        return run

    def sast_stage(self, run):
        return "ok", {"high": 0, "medium": 0, "low": 0, "warnings": [self.WARNING]}, [], "high 0, medium 0, low 0"

    def test_stage_keeps_its_status_and_carries_the_warning(self):
        run = self.fake_run()
        [rec] = stages.execute(run, "sast", "SAST (Semgrep)", "sast", self.sast_stage)
        self.assertEqual((rec.status, rec.reasons, rec.warnings), ("passed", [], [self.WARNING]))
        self.assertIn(f"stage warning: SAST (Semgrep): {self.WARNING}", run.logged)

    def test_stage_without_warnings_has_an_empty_list(self):
        run = self.fake_run()
        [rec] = stages.execute(run, "secrets", "Secret scan (Gitleaks)", "secrets",
                               lambda run: ("ok", {"findings": 0}, [], "0 finding(s)"))
        self.assertEqual(rec.warnings, [])

    def test_run_summary_lists_warnings(self):
        run = self.fake_run()
        stages.execute(run, "sast", "SAST (Semgrep)", "sast", self.sast_stage)
        run.repo = types.SimpleNamespace(name="GMshield-sample")
        run.branch, run.short, run.sha, run.id, run.mode = "develop", "abcdef12", "abcdef12" * 5, "run-1", "full"
        run.result, run.commit, run.release_tag, run.notes = "passed", {}, None, []
        text = report._markdown(run, {"seconds": 5, "host": "test"})
        self.assertIn("· PASSED, 1 warning", text.splitlines()[0])
        self.assertIn("## Warnings", text)
        self.assertIn(f"- **SAST (Semgrep):** {self.WARNING}", text)

    def test_workstation_release_page_lists_warnings(self):
        spec = importlib.util.spec_from_file_location("gmshield_results",
                                                      RUNNER_DIR / "workstation" / "gmshield-results.py")
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        stage = {"key": "sast", "title": "SAST (Semgrep)", "status": "passed", "detail": "high 0", "threshold": "-",
                 "files": [], "reasons": []}
        run = {"repo": "GMshield-sample", "branch": "develop", "sha": "abcdef12" * 5, "run": "run-1",
               "result": "passed", "started": "2026-11-10T12:00:00+00:00", "commit": {}, "stages": [stage]}
        self.assertNotIn("## Warnings", tool.release_md(run))            # runs from before warnings existed
        stage["warnings"] = [self.WARNING]
        text = tool.release_md(run)
        self.assertIn("1 warning, listed below.", text)
        self.assertIn(f"- **SAST (Semgrep):** {self.WARNING}", text)


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


class SettingsTest(unittest.TestCase):
    def test_instance_label_differs_per_installation(self):
        """Crash cleanup is scoped by instance: a test install must never match the live one."""
        import os
        from gmshield_ci.config import load_settings
        saved = os.environ.get("GMSHIELD_HOME")
        try:
            os.environ["GMSHIELD_HOME"] = "/tmp/gmshield-a"
            a = load_settings().instance
            os.environ["GMSHIELD_HOME"] = "/tmp/gmshield-b"
            b = load_settings().instance
            os.environ["GMSHIELD_HOME"] = "/tmp/gmshield-a"
            a_again = load_settings().instance
        finally:
            if saved is None:
                os.environ.pop("GMSHIELD_HOME", None)
            else:
                os.environ["GMSHIELD_HOME"] = saved
        self.assertNotEqual(a, b)
        self.assertEqual(a, a_again)


if __name__ == "__main__":
    unittest.main()
