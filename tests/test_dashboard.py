"""Unit tests for the tty1 dashboard: it reads the pipeline's files and never writes. Run: python3 -m unittest -v"""
import fcntl
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from gmshield_ci import dashboard
from gmshield_ci.config import Repo, Settings

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def _settings(home: Path) -> Settings:
    return Settings(home=home, org="GMshield", branches=("develop", "main"), registry="", prod_network="",
                    ci_slice="", repos=[Repo("GMshield-backend", ""), Repo("GMshield-worker", "")], images={},
                    semgrep_rulesets=[], limits={}, gates={})


def _run(home: Path, repo: str, branch: str, run: str, result: str, started: str, mode: str = "full",
         release=None, stages=None, subject="feat: something", finished=True) -> None:
    d = home / "artifacts" / repo / branch / run
    d.mkdir(parents=True)
    (d / "pipeline.log").write_text(f"12:00:00Z [{repo}/{branch}@abc] run {run} started ({mode})\n"
                                    f"12:00:05Z [{repo}/{branch}@abc] SAST (Semgrep): running\n")
    if not finished:
        return
    (d / "summary.json").write_text(json.dumps({"result": result, "stages": stages or []}))
    with open(d.parent / "history.jsonl", "a") as fh:
        fh.write(json.dumps({"run": run, "mode": mode, "result": result, "sha": "0a827d611b7d8cbd" + run[-4:],
                             "started": started, "seconds": 95.0, "release": release, "warnings": 0,
                             "subject": subject}) + "\n")


class DashboardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.s = _settings(self.home)
        (self.home / "state").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def frame(self, snap=None, cols=140, rows=40):
        snap = snap or dashboard.collect(self.s, timer=False)
        return "\n".join(dashboard.render(snap, cols, rows, NOW, False, "srv",
                                          [r.name for r in self.s.repos], self.s.branches))

    def test_latest_full_run_per_branch_and_blocking_gate(self):
        _run(self.home, "GMshield-backend", "develop", "20261110-100000-aaaa", "passed", "2026-11-10T10:00:00+00:00")
        _run(self.home, "GMshield-backend", "develop", "20261110-110000-bbbb", "failed", "2026-11-10T11:00:00+00:00",
             stages=[{"key": "sast", "title": "SAST (Semgrep)", "status": "failed", "reasons": ["high 2 > 0"]},
                     {"key": "secrets", "title": "Secret scan (Gitleaks)", "status": "passed", "reasons": []}])
        _run(self.home, "GMshield-backend", "develop", "20261110-110500-cccc", "passed",
             "2026-11-10T11:05:00+00:00", mode="light")
        snap = dashboard.collect(self.s, timer=False)
        latest = snap.latest[("GMshield-backend", "develop")]
        self.assertEqual(latest["run"], "20261110-110000-bbbb")          # light runs do not count
        self.assertEqual(latest["blockers"], ["SAST (Semgrep): high 2 > 0"])
        self.assertEqual(latest["stages"], {"sast": "failed", "secrets": "passed"})
        text = self.frame(snap, cols=100)
        self.assertIn("FAILED", text)
        self.assertIn("✗ backend: SAST (Semgrep): high 2 > 0", text)
        self.assertIn("not run yet", text)                               # backend main, worker
        self.assertEqual([r[2]["run"] for r in snap.recent],
                         ["20261110-110500-cccc", "20261110-110000-bbbb", "20261110-100000-aaaa"])

    def test_newest_release(self):
        _run(self.home, "GMshield-backend", "main", "20261109-100000-aaaa", "passed", "2026-11-09T10:00:00+00:00",
             release="r2026.11.09-1000-aaaa")
        _run(self.home, "GMshield-worker", "main", "20261110-090000-bbbb", "passed", "2026-11-10T09:00:00+00:00",
             release="r2026.11.10-0900-bbbb")
        _run(self.home, "GMshield-worker", "main", "20261110-100000-cccc", "blocked", "2026-11-10T10:00:00+00:00",
             stages=[{"key": "promotion", "title": "Promotion check", "status": "failed", "reasons": []}])
        text = self.frame()
        self.assertIn("Latest release: r2026.11.10-0900-bbbb (worker, 3h 00m ago)", text)
        self.assertIn("BLOCKED", text)
        self.assertIn("Promotion check", text)

    def test_running_only_while_the_poll_lock_is_held(self):
        _run(self.home, "GMshield-worker", "develop", "20261110-115800-dddd", "", "", finished=False)
        self.assertIsNone(dashboard.collect(self.s, timer=False).running)  # stale folder of a crashed run
        lock = self.home / "state" / "poll.lock"
        with open(lock, "w") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            snap = dashboard.collect(self.s, timer=False)
        self.assertTrue(snap.poll_active)
        self.assertEqual((snap.running.repo, snap.running.branch), ("GMshield-worker", "develop"))
        self.assertEqual(snap.running.last_line, "SAST (Semgrep): running")
        text = self.frame(snap)
        self.assertIn("RUNNING worker dddd · 2m ago · SAST (Semgrep): running", text)
        with open(lock, "w") as fh:                                        # released: the lock is free again
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_lock_parsing_ignores_waiters_and_other_files(self):
        lock = self.home / "state" / "poll.lock"
        lock.write_text("")
        st = lock.stat()
        dev = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}"
        proc = self.home / "locks"
        proc.write_text(f"1: FLOCK  ADVISORY  WRITE 99 {dev}:{st.st_ino + 1} 0 EOF\n"
                        f"2: -> FLOCK  ADVISORY  WRITE 98 {dev}:{st.st_ino} 0 EOF\n")
        self.assertFalse(dashboard.lock_held(lock, proc))
        proc.write_text(f"1: FLOCK  ADVISORY  WRITE 99 {dev}:{st.st_ino} 0 EOF\n")
        self.assertTrue(dashboard.lock_held(lock, proc))

    def test_corrupt_history_lines_are_skipped_and_frame_fits(self):
        _run(self.home, "GMshield-backend", "develop", "20261110-100000-aaaa", "passed", "2026-11-10T10:00:00+00:00",
             subject="x" * 300)
        with open(self.home / "artifacts" / "GMshield-backend" / "develop" / "history.jsonl", "a") as fh:
            fh.write('{"run": "half-writ')
        (self.home / "PAUSED").touch()
        lines = dashboard.render(dashboard.collect(self.s, timer=False), 80, 24, NOW)
        self.assertEqual(len(lines), 24)
        self.assertTrue(all(len(l) <= 80 for l in lines))
        self.assertIn("PAUSED", "\n".join(lines))

    def test_each_branch_has_its_own_section_with_the_failed_stage_marked(self):
        dev = [{"key": k, "title": k, "status": "passed", "reasons": []}
               for k, _, _ in dashboard.STAGES["develop"]]
        dev[6] = {"key": "sonar", "title": "SAST & quality (SonarQube)", "status": "failed",
                  "reasons": ["hotspots reviewed 0% < 100%"]}
        _run(self.home, "GMshield-backend", "develop", "20261110-100000-aaaa", "failed",
             "2026-11-10T10:00:00+00:00", stages=dev)
        _run(self.home, "GMshield-backend", "main", "20261110-100500-bbbb", "blocked", "2026-11-10T10:05:00+00:00",
             stages=[{"key": "resolve", "status": "passed"},
                     {"key": "promotion", "title": "Promotion check (passed develop)", "status": "failed",
                      "reasons": ["tree never passed develop"]}])
        lines = self.frame(cols=100, rows=60).splitlines()
        dev_at = next(i for i, l in enumerate(lines) if l.startswith(" DEVELOP"))
        main_at = next(i for i, l in enumerate(lines) if l.startswith(" MAIN"))
        self.assertLess(dev_at, main_at)
        dev_part, main_part = lines[dev_at:main_at], lines[main_at:]

        def cells(part, label_row_prefix):
            header = next(l for l in part if l.startswith(" Repo"))
            row = next(l for l in part if l.startswith(label_row_prefix))
            return header, row
        header, row = cells(dev_part, " backend")
        self.assertEqual(row[header.index("Sonr"):].split()[0], "FAIL")
        self.assertEqual(row[header.index("Semg"):].split()[0], "ok")
        self.assertIn("1 of 2 not passing", dev_part[0])
        header, row = cells(main_part, " backend")
        self.assertEqual(row[header.index("Prom"):].split()[0], "FAIL")
        self.assertEqual(row[header.index("Img"):].split()[0], "·")       # never reached
        self.assertIn("BLOCKED", row)
        self.assertTrue(any("✗ backend: Promotion check (passed develop): tree never passed develop" in l
                            for l in main_part))
        self.assertFalse(any("Promotion check" in l for l in dev_part))

    def test_wide_screen_puts_sections_side_by_side(self):
        _run(self.home, "GMshield-backend", "develop", "20261110-100000-aaaa", "passed", "2026-11-10T10:00:00+00:00")
        lines = dashboard.render(dashboard.collect(self.s, timer=False), 170, 48, NOW, False, "srv",
                                 [r.name for r in self.s.repos])
        self.assertEqual(len(lines), 48)
        self.assertTrue(all(len(l) <= 170 for l in lines))
        self.assertTrue(any(l.startswith(" DEVELOP") and " MAIN " in l for l in lines))
        colored = dashboard.render(dashboard.collect(self.s, timer=False), 170, 48, NOW, True)
        self.assertEqual(len(colored), 48)

    def test_stopped_timer_is_shown(self):
        snap = dashboard.Snapshot(timer="inactive")
        self.assertIn("Poller timer INACTIVE", self.frame(snap))

    def test_empty_install(self):
        text = self.frame()
        self.assertIn("Latest release: none yet", text)
        self.assertIn("no runs yet", text)


if __name__ == "__main__":
    unittest.main()
