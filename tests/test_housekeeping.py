"""Unit tests for housekeeping's decisions: when it runs and what it keeps. Run: python3 -m unittest -v"""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from gmshield_ci import housekeeping as hk
from gmshield_ci.config import Settings

NOW = datetime(2026, 12, 20, 7, 0, tzinfo=timezone.utc)        # 04:00 in America/Sao_Paulo: inside the window


def _settings(home: Path = Path("/nonexistent"), **housekeeping) -> Settings:
    return Settings(home=home, org="GMshield", branches=("develop", "main"), registry="localhost:5000",
                    prod_network="", ci_slice="", repos=[], images={}, semgrep_rulesets=[],
                    limits={"keep_images_per_service": 3}, gates={}, housekeeping=housekeeping)


def _img(repo, tag, days_old, id_=None):
    return hk.Image(id_ or f"sha256:{repo}{tag}", repo, tag, NOW - timedelta(days=days_old))


class DueTest(unittest.TestCase):
    def test_runs_once_a_day_inside_the_quiet_window(self):
        s = _settings()
        self.assertEqual(hk.due(s, NOW, None, 50), "daily")
        self.assertEqual(hk.due(s, NOW, NOW - timedelta(hours=21), 50), "daily")
        self.assertIsNone(hk.due(s, NOW, NOW - timedelta(hours=2), 50))

    def test_never_outside_the_window_while_the_disk_has_room(self):
        self.assertIsNone(hk.due(_settings(), NOW.replace(hour=18), None, 50))     # 15:00 local

    def test_low_disk_runs_at_once_but_at_most_hourly(self):
        afternoon = NOW.replace(hour=18)
        self.assertTrue(hk.due(_settings(), afternoon, None, 10).startswith("low disk"))
        self.assertIsNone(hk.due(_settings(), afternoon, afternoon - timedelta(minutes=30), 10))
        self.assertIsNotNone(hk.due(_settings(), afternoon, afternoon - timedelta(minutes=61), 10))


    def test_once_after_each_boot_once_the_stack_had_time_to_start(self):
        afternoon = NOW.replace(hour=18)                                          # outside the window
        booted = afternoon - timedelta(minutes=30)
        self.assertEqual(hk.due(_settings(), afternoon, afternoon - timedelta(days=2), 50, booted), "after boot")
        self.assertEqual(hk.due(_settings(), afternoon, None, 50, booted), "after boot")
        self.assertIsNone(hk.due(_settings(), afternoon, booted + timedelta(minutes=12), 50, booted))  # done
        just_booted = afternoon - timedelta(minutes=3)
        self.assertIsNone(hk.due(_settings(), afternoon, afternoon - timedelta(days=2), 50, just_booted))


class RunFoldersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.branch = Path(self.tmp.name) / "GMshield-backend" / "develop"
        self.branch.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, days_old: int, sha: str) -> str:
        name = f"{NOW - timedelta(days=days_old):%Y%m%d-%H%M%S}-{sha}"
        (self.branch / name).mkdir()
        return name

    def test_old_runs_go_but_the_newest_latest_and_protected_stay(self):
        oldest = self._run(60, "aaaaaaaa")
        released = self._run(50, "bbbbbbbb")
        old_latest = self._run(45, "cccccccc")
        older = self._run(40, "dddddddd")
        recent = self._run(5, "eeeeeeee")
        newest = self._run(1, "ffffffff")
        (self.branch / "latest").symlink_to(old_latest)
        (self.branch / "history.jsonl").write_text("{}\n")
        gone = hk.runs_to_delete(self.branch, NOW, max_age_days=30, keep_newest=2, protected={released})
        self.assertEqual([p.name for p in gone], [oldest, older])
        self.assertNotIn(recent, [p.name for p in gone])
        self.assertNotIn(newest, [p.name for p in gone])

    def test_keep_newest_wins_over_age(self):
        names = [self._run(100 + i, f"{i:08x}") for i in range(3)]
        self.assertEqual(hk.runs_to_delete(self.branch, NOW, 30, keep_newest=5, protected=set()), [])
        self.assertEqual(len(names), 3)

    def test_protected_runs_come_from_releases_and_state(self):
        root = Path(self.tmp.name)
        rel = root / "GMshield-backend" / "releases" / "r2026.11.01-0000-abcdef12"
        rel.mkdir(parents=True)
        (rel / "run").symlink_to(Path("..") / ".." / "main" / "20261101-000000-abcdef12")
        state = {"GMshield-backend": {"develop": {"run": "20261102-000000-12345678"}}}
        self.assertEqual(hk.protected_runs(root, state), {"20261101-000000-abcdef12", "20261102-000000-12345678"})


class ImagesTest(unittest.TestCase):
    def test_production_tags_keep_prod_in_use_and_newest(self):
        reg = "localhost:5000/gmshield-backend"
        images = [_img(reg, "prod", 3, "sha256:p"), _img(reg, "s1", 1), _img(reg, "s2", 2), _img(reg, "s3", 3),
                  _img(reg, "s4", 4), _img(reg, "s5", 5), _img(reg, "running", 9, "sha256:run")]
        out = dict(hk.images_to_remove(_settings(), images, {"sha256:run"}, NOW))
        self.assertEqual(sorted(out), [f"{reg}:s4", f"{reg}:s5"])

    def test_ci_images_keep_newest_and_drop_inactive_services(self):
        images = [_img("gmshield-ci/worker", f"w{i}", i) for i in range(5)]
        images += [_img("gmshield-ci/sample", f"x{i}", 40 + i) for i in range(2)]
        out = dict(hk.images_to_remove(_settings(), images, set(), NOW))
        self.assertEqual(sorted(out), ["gmshield-ci/sample:x0", "gmshield-ci/sample:x1",
                                       "gmshield-ci/worker:w3", "gmshield-ci/worker:w4"])

    def test_other_images_only_when_old_unused_and_unpinned(self):
        images = [_img("alpine", "latest", 12), _img("python", "3.10-slim", 400),
                  _img("gitleaks", "<none>", 500, "sha256:pinned"), _img("qdrant/qdrant", "v1", 420, "sha256:used")]
        out = dict(hk.images_to_remove(_settings(), images, {"sha256:pinned", "sha256:used"}, NOW))
        self.assertEqual(list(out), ["python:3.10-slim"])

    def test_untagged_images_are_removed_by_id(self):
        out = hk.images_to_remove(_settings(), [_img("redis", "<none>", 200, "sha256:r")], set(), NOW)
        self.assertEqual(out[0][0], "sha256:r")


if __name__ == "__main__":
    unittest.main()
