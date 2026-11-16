"""The NFR-1 gate (Story 1.7): the [nfr1] contract table, the encodings searched, the gate's verdict, and
the check inside the staging session with Docker replaced by a recorder (planted plaintext included).
Run: python3 -m unittest tests.test_nfr1 -v"""
import base64
import io
import json
import shutil
import tarfile
import tempfile
import threading
import tomllib
import types
import unittest
from pathlib import Path
from unittest import mock

from gmshield_ci import config, gates, pipeline, stages
from gmshield_ci.config import RUNNER_DIR, ContractError
from tests.test_contract import RUN_ID, SHA, FakeDocker, contract_from, settings

GATES = tomllib.loads((RUNNER_DIR / "gates.toml").read_text())
TEXT = "GMshield-NFR1-probe-0123456789abcdef0123456789abcdef"
PROBE_ID = "0195a3c0-1111-7000-8000-000000000001"
NFR1 = ('[nfr1]\nseed_path = "/internal/v1/test-mode/nfr1-probe"\n'
        'readback_path = "/internal/v1/test-mode/nfr1-probe/{id}"\n')
BACKEND = ('[service]\nport = 8080\n[deploy]\nuser = "10001:10001"\nread_only = true\n'
           'mounts = [{ name = "files", target = "/var/lib/gmshield/files" }]\n'
           '[staging]\nservices = ["postgres", "redis"]\n' + NFR1)


def volume_tar(*files: str) -> bytes:
    """A `docker cp ... -` copy of a volume: its folder, plus one entry per name given."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        folder = tarfile.TarInfo("files")
        folder.type = tarfile.DIRTYPE
        tar.addfile(folder)
        for name in files:
            data = b"\x01ciphertext"
            info = tarfile.TarInfo(f"files/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class ContractTest(unittest.TestCase):
    def test_both_routes_are_read(self):
        c = contract_from('[service]\nport = 8080\n' + NFR1)
        self.assertTrue(c.nfr1)
        self.assertEqual(c.nfr1_seed_path, "/internal/v1/test-mode/nfr1-probe")
        self.assertEqual(c.nfr1_readback_path, "/internal/v1/test-mode/nfr1-probe/{id}")

    def test_without_the_table_there_is_no_gate(self):
        self.assertFalse(contract_from('[service]\nport = 8080\n').nfr1)

    def test_refusals_name_the_key(self):
        for text, key in (
                ('[service]\nport = 8080\n[nfr1]\nseed_path = "/a"\n', r"\[nfr1\].readback_path is required"),
                ('[service]\nport = 8080\n[nfr1]\nreadback_path = "/a/{id}"\n', r"\[nfr1\].seed_path is required"),
                ('[service]\nport = 8080\n[nfr1]\nseed_path = "/a"\nreadback_path = "/a"\n', r"\{id\} once"),
                ('[service]\nport = 8080\n[nfr1]\nseed_path = "/a"\nreadback_path = "/a/{id}/{id}"\n', r"\{id\} once"),
                ('[service]\nport = 8080\n[nfr1]\nseed_path = "/a"\nreadback_path = "/a/{id}\'x"\n', r"readback_path"),
                ('[service]\nport = 8080\n[nfr1]\nseed_path = "/a b"\nreadback_path = "/a/{id}"\n', r"seed_path"),
                ('[service]\nport = 8080\n[nfr1]\nseed_path = "/a"\nreadback_path = "/a/{id}"\nextra = 1\n', "unknown key"),
                ('[nfr1]\nseed_path = "/a"\nreadback_path = "/a/{id}"\n', r"needs \[service\].port"),
                ('nfr1 = "yes"\n[service]\nport = 8080\n', r"\[nfr1\] must be a table")):
            with self.subTest(text=text), self.assertRaisesRegex(ContractError, key):
                contract_from(text)

    def test_backend_contract_shape_is_accepted(self):
        c = contract_from(BACKEND)
        self.assertTrue(c.nfr1)
        self.assertEqual([(m.name, m.target) for m in c.mounts], [("files", "/var/lib/gmshield/files")])


class NeedleTest(unittest.TestCase):
    def test_text_is_random_for_each_run_and_survives_url_encoding(self):
        from urllib.parse import quote, quote_plus
        a, b = stages.nfr1_text(), stages.nfr1_text()
        self.assertNotEqual(a, b)
        self.assertRegex(a, r"^[A-Za-z0-9-]+$")
        self.assertEqual((quote(a), quote_plus(a)), (a, a))

    def test_json_escaped_base64_and_uppercase_hex_are_found(self):
        # The run's own text (letters, digits, hyphens) never encodes to "/" or "+"; a text with "?" does,
        # so the escaped needles are exercised on one.
        odd = "probe???text???end"
        needles = stages.nfr1_needles(odd)
        self.assertTrue(any(b"\\/" in n for n in needles["base64"]))
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "store"
            for prefix in (b"", b"x", b"xy"):
                enc = base64.b64encode(prefix + odd.encode())
                self.assertIn(b"/", enc)
                with self.subTest(prefix=prefix):
                    f.write_bytes(b'{"v":"' + enc.replace(b"/", b"\\/") + b'"}')
                    self.assertIn("base64", stages.nfr1_search(f, needles))
            f.write_bytes(b"0x" + TEXT.encode().hex().upper().encode())
            self.assertEqual(stages.nfr1_search(f, stages.nfr1_needles(TEXT)), ["hex"])

    def test_base64_is_found_at_every_alignment_inside_a_longer_value(self):
        needles = stages.nfr1_needles(TEXT)
        for prefix in (b"", b"x", b"xy", b"xyz", b"{\"k\":\"long prefix\""):
            for suffix in (b"", b"!", b"!?", b" and more"):
                stream = prefix + TEXT.encode() + suffix
                enc, url = base64.b64encode(stream), base64.urlsafe_b64encode(stream)
                with self.subTest(prefix=prefix, suffix=suffix):
                    self.assertTrue(any(n in enc for n in needles["base64"]))
                    self.assertTrue(any(n in url for n in needles["base64url"]))

    def test_each_encoding_is_named_and_unrelated_text_is_not_found(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "store"
            needles = stages.nfr1_needles(TEXT)
            for content, found in ((b"nothing here", []), (b"..." + TEXT.encode() + b"...", ["plain"]),
                                   (b"\\x" + TEXT.encode().hex().encode(), ["hex"]),
                                   (base64.b64encode(b"ab" + TEXT.encode()), ["base64", "base64url"])):
                f.write_bytes(content)
                self.assertEqual(stages.nfr1_search(f, needles), found)

    def test_text_across_a_chunk_boundary_is_found(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(stages, "_CHUNK", 16):
            f = Path(d) / "store"
            f.write_bytes(b"z" * 23 + TEXT.encode() + b"z" * 40)
            self.assertEqual(stages.nfr1_search(f, stages.nfr1_needles(TEXT)), ["plain"])


class GateTest(unittest.TestCase):
    STORES = [{"store": "database (pg_dump)", "bytes": 10, "found": []}]

    def judge(self, metrics, outcome="ok"):
        return gates.judge("nfr1", outcome, metrics, GATES)

    def test_seeded_read_back_and_found_nowhere_passes(self):
        status, threshold, reasons = self.judge({"seeded": True, "read_back": True, "stores": self.STORES, "found_in": []})
        self.assertEqual((status, reasons), ("passed", []))
        self.assertIn("found in no store", threshold)

    def test_found_seeding_or_read_back_failures_block(self):
        cases = (({"seeded": True, "read_back": True, "found_in": ["Redis (RDB) (plain)"]}, "found in Redis (RDB)"),
                 ({"seeded": False, "read_back": False, "seed_problem": "POST /a failed"}, "seeding failed: POST /a"),
                 ({"seeded": True, "read_back": False, "seed_problem": "GET /a/{id} did not return the text"},
                  "did not return the text"))
        for metrics, reason in cases:
            status, _, reasons = self.judge({"stores": self.STORES, "found_in": [], **metrics})
            self.assertEqual(status, "failed")
            self.assertTrue(any(reason in r for r in reasons), reasons)

    def test_nothing_searched_or_an_error_blocks_and_a_skip_skips(self):
        self.assertEqual(self.judge({"seeded": True, "read_back": True, "stores": [], "found_in": []})[0], "failed")
        self.assertEqual(self.judge({"error": "pg_dump failed"}, outcome="error")[0], "failed")
        self.assertEqual(self.judge({}, outcome="skipped")[0], "skipped")

    def test_a_store_without_the_seeded_data_blocks(self):
        status, _, reasons = self.judge({"seeded": True, "read_back": True, "stores": self.STORES, "found_in": [],
                                         "missing_evidence": ["volume 'files' (/data): it holds no file"]})
        self.assertEqual(status, "failed")
        self.assertIn("no trace of the seeded data in volume 'files' (/data): it holds no file", reasons)


class StagingCheckTest(unittest.TestCase):
    """The check inside dast_staging, with Docker recorded and each store's content chosen by the test."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cmds = []
        self.content = {"pg": b"COPY vault_probe ... " + PROBE_ID.encode() + b" \\x01ab\n", "rdb": b"REDIS0012...",
                        "volume": volume_tar("owner/file/0.piece"),
                        "app": b'{"event":"request.completed"}\n', "postgres": b"LOG ready\n", "redis": b"Ready\n"}
        self.rc = {}
        self.readback = {"text": TEXT, "fileText": TEXT}
        for p in (mock.patch.object(stages, "sh", self.fake_sh),
                  mock.patch.object(stages, "capture", self.fake_capture),
                  mock.patch.object(stages, "capture_to", self.fake_capture_to),
                  mock.patch.object(stages, "container_logs", self.fake_logs),
                  mock.patch.object(stages, "_zap", lambda run, net, base, outdir, active: ("ok", {}, [], "zap")),
                  mock.patch.object(stages, "nfr1_text", lambda: TEXT)):
            p.start()
            self.addCleanup(p.stop)

    def fake_sh(self, cmd, log=None, timeout=600, env=None, cwd=None):
        self.cmds.append(cmd)
        if cmd[:2] == ["docker", "exec"] and "--rdb" in cmd:
            return self.rc.get("rdb", 0)
        return 0

    def fake_capture(self, cmd, timeout=120):
        self.cmds.append(cmd)
        if cmd[:2] == ["docker", "exec"]:
            return 0, "PONG" if "redis-cli" in cmd else "accepting connections"
        return 0, ""

    def fake_capture_to(self, cmd, dest, log=None, timeout=600):
        self.cmds.append(cmd)
        kind = "pg" if "pg_dump" in cmd else "rdb" if "cat" in cmd else "volume"
        Path(dest).write_bytes(self.content[kind])
        return self.rc.get(kind, 0)

    def fake_logs(self, name, dest):
        Path(dest).write_bytes(self.content.get(name.rsplit("-", 1)[-1], b"log"))

    def run_for(self, text=BACKEND):
        test = self

        class Docker(FakeDocker):
            def run(self, name, image, args, **kw):
                self.calls.append((name, image, args, kw))
                work = kw["mounts"][0][0] if kw.get("mounts") else None
                if name == "nfr1-seed":
                    (work / "nfr1-seed.json").write_text(json.dumps({"id": PROBE_ID}))
                elif name == "nfr1-readback":
                    (work / "nfr1-readback.json").write_text(json.dumps(test.readback))
                return test.rc.get(name, 0)

        s = settings(self.tmp / "home")
        d = self.tmp / "artifacts"
        d.mkdir(exist_ok=True)
        return types.SimpleNamespace(
            s=s, contract=contract_from(text, "FROM a AS test\nFROM b\n", repo="GMshield-api"), id=RUN_ID, sha=SHA,
            dir=d, work=self.tmp / "work", src=self.tmp / "src", docker=Docker(), local_image=f"gmshield-ci/api:{SHA}",
            image_built=True, repo=types.SimpleNamespace(url="file:///x"), log=lambda m: None, lock=threading.Lock(),
            records=[], titles={})

    def nfr1(self, run):
        outcome, _, _, detail = stages.dast_staging(run)
        self.assertEqual(outcome, "ok", detail)
        [rec] = [r for r in run.records if r.key == "nfr1"]
        return rec

    def test_clean_run_passes_and_lists_every_store_searched(self):
        run = self.run_for()
        rec = self.nfr1(run)
        self.assertEqual(rec.status, "passed", rec.reasons)
        self.assertEqual([x["store"] for x in rec.metrics["stores"]],
                         ["database (pg_dump)", "Redis (RDB)", "volume 'files' (/var/lib/gmshield/files)",
                          "app log", "postgres log", "redis log"])
        artifact = json.loads((run.dir / "nfr1" / "nfr1.json").read_text())
        self.assertEqual(len(artifact["stores"]), 6)
        self.assertIn("nfr1/nfr1.json", rec.files)
        self.assertNotIn(TEXT, (run.dir / "nfr1" / "nfr1.json").read_text())

    def test_seed_and_read_back_go_through_the_contract_routes_inside_the_network(self):
        run = self.run_for()
        self.nfr1(run)
        calls = {c[0]: c for c in run.docker.calls}
        seed, back = calls["nfr1-seed"], calls["nfr1-readback"]
        self.assertEqual(seed[2][-1], "http://app:8080/internal/v1/test-mode/nfr1-probe")
        self.assertIn("POST", seed[2])
        self.assertEqual(back[2][-1], f"http://app:8080/internal/v1/test-mode/nfr1-probe/{PROBE_ID}")
        self.assertEqual(seed[3]["network"], f"gmshield-ci-{RUN_ID}")
        request = json.loads((run.work / "nfr1" / "seed-request.json").read_text())
        self.assertEqual(request, {"text": TEXT})
        self.assertNotIn(TEXT, " ".join(seed[2]))                     # the text never reaches a command line

    def test_the_stores_are_copied_before_the_staging_session_is_torn_down(self):
        run = self.run_for()
        self.nfr1(run)
        pg = next(i for i, c in enumerate(self.cmds) if "pg_dump" in c)
        rdb = next(i for i, c in enumerate(self.cmds) if "--rdb" in c)
        vol = next(i for i, c in enumerate(self.cmds) if c[:2] == ["docker", "cp"] and c[-1] == "-")
        teardown = next(i for i, c in enumerate(self.cmds) if c[:4] == ["docker", "rm", "-f", "-v"])
        self.assertLess(max(pg, rdb, vol), teardown)
        self.assertEqual(self.cmds[pg][:3], ["docker", "exec", f"gmshield-ci-{RUN_ID}-staging-postgres"])
        self.assertEqual(self.cmds[vol][2], f"gmshield-ci-{RUN_ID}-app:/var/lib/gmshield/files")

    def test_stores_without_the_seeded_data_fail_the_gate(self):
        # "Not found" proves nothing where the probe's data never went (e.g. a files dir that is not the volume).
        cases = {"volume": (volume_tar(), "volume 'files' (/var/lib/gmshield/files): it holds no file"),
                 "pg": (b"COPY vault_probe ... (no rows)\n", f"database (pg_dump): the seeded id {PROBE_ID} is not in it")}
        for kind, (content, missing) in cases.items():
            with self.subTest(store=kind):
                self.setUp()
                self.content[kind] = content
                rec = self.nfr1(self.run_for())
                self.assertEqual(rec.status, "failed")
                self.assertEqual(rec.metrics["missing_evidence"], [missing])
                self.assertIn(f"no trace of the seeded data in {missing}", rec.reasons)

    def test_a_clean_run_has_the_seeded_data_in_every_store_it_needs(self):
        rec = self.nfr1(self.run_for())
        self.assertEqual(rec.metrics["missing_evidence"], [])

    def test_the_redis_dump_stays_in_redis_own_data_folder(self):
        # SonarQube S5443: never a publicly writable directory such as /tmp.
        self.nfr1(self.run_for())
        redis = f"gmshield-ci-{RUN_ID}-staging-redis"
        self.assertIn(["docker", "exec", redis, "redis-cli", "--rdb", "/data/gmshield-nfr1.rdb"], self.cmds)
        self.assertIn(["docker", "exec", redis, "cat", "/data/gmshield-nfr1.rdb"], self.cmds)
        self.assertFalse(any("/tmp" in part for c in self.cmds for part in c if isinstance(part, str)
                             and "gmshield-nfr1" in part))

    def test_planted_plaintext_fails_the_gate_and_names_the_store(self):
        planted = {"pg": ("INSERT ... '" + PROBE_ID + "', '" + TEXT + "'").encode(),
                   "rdb": b"REDIS" + base64.b64encode(b"z" + TEXT.encode()),
                   "volume": volume_tar("owner/file/0.piece") + TEXT.encode(),
                   "app": b'{"event":"x","note":"' + TEXT.encode() + b'"}',
                   "redis": b"\\x" + TEXT.encode().hex().encode()}
        names = {"pg": "database (pg_dump) (plain)", "rdb": "Redis (RDB) (base64, base64url)",
                 "volume": "volume 'files' (/var/lib/gmshield/files) (plain)", "app": "app log (plain)",
                 "redis": "redis log (hex)"}
        for kind, content in planted.items():
            with self.subTest(store=kind):
                self.setUp()
                self.content[kind] = content
                rec = self.nfr1(self.run_for())
                self.assertEqual(rec.status, "failed")
                self.assertEqual(rec.reasons, [f"known text found in {names[kind]}"])

    def test_seeding_or_read_back_that_fails_blocks(self):
        for change, reason in ((lambda: self.rc.update({"nfr1-seed": 22}), "seeding failed"),
                               (lambda: self.readback.update({"fileText": "something else"}), "did not return the text"),
                               (lambda: self.readback.clear(), "did not return the text")):
            with self.subTest(reason=reason):
                self.setUp()
                change()
                rec = self.nfr1(self.run_for())
                self.assertEqual(rec.status, "failed")
                self.assertTrue(any(reason in r for r in rec.reasons), rec.reasons)

    def test_a_store_that_cannot_be_copied_is_an_error(self):
        for kind, words in (("pg", "pg_dump"), ("rdb", "Redis RDB"), ("volume", "volume 'files'")):
            with self.subTest(store=kind):
                self.setUp()
                self.rc[kind] = 1
                rec = self.nfr1(self.run_for())
                self.assertEqual((rec.outcome, rec.status), ("error", "failed"))
                self.assertIn(words, rec.reasons[0])

    def test_a_failed_copy_still_names_where_the_text_was_already_found(self):
        self.content["pg"] = ("INSERT '" + TEXT + "'").encode()
        self.rc["volume"] = 1
        rec = self.nfr1(self.run_for())
        self.assertEqual((rec.outcome, rec.status), ("error", "failed"))
        self.assertIn("already FOUND in database (pg_dump) (plain)", rec.reasons[0])
        self.assertIn("already FOUND in database (pg_dump)", rec.detail)
        self.assertEqual(rec.metrics["found_in"], ["database (pg_dump) (plain)"])

    def test_without_the_table_the_session_runs_no_check(self):
        run = self.run_for(BACKEND.split("[nfr1]")[0])
        stages.dast_staging(run)
        self.assertEqual(run.records, [])
        self.assertNotIn("nfr1-seed", [c[0] for c in run.docker.calls])

    def test_redis_keeps_values_uncompressed_in_its_rdb(self):
        args = stages.SERVICE_SPECS["redis"]["args"]
        self.assertEqual(args[args.index("--rdbcompression") + 1], "no")


class FlowTest(unittest.TestCase):
    """develop: a contract with [nfr1] whose staging session never reached the check still gets a verdict."""

    def flow(self, contract):
        run = types.SimpleNamespace(mode="full", old=None, sha=SHA, records=[], notes=[], id=RUN_ID, tree="t",
                                    contract=contract, repo=types.SimpleNamespace(name="GMshield-x"),
                                    s=types.SimpleNamespace(state_dir=Path(tempfile.mkdtemp()), gates=GATES),
                                    log=lambda m: None, lock=threading.Lock(), titles={})
        self.addCleanup(shutil.rmtree, run.s.state_dir, ignore_errors=True)
        with mock.patch.object(pipeline, "_source_checks", lambda *a, **k: None), \
                mock.patch.object(pipeline.sonar, "analyze", lambda run: ("ok", {"status": "OK"}, [], "ok")), \
                mock.patch.object(pipeline.stages, "image", lambda run: ("skipped", {}, [], "")), \
                mock.patch.object(pipeline.stages, "integration_tests", lambda run: ("skipped", {}, [], "")), \
                mock.patch.object(pipeline.stages, "dast_staging", lambda run: ("error", {"error": "app not healthy"},
                                                                                 [], "app not healthy")):
            pipeline.develop_flow(run)
        [rec] = [r for r in run.records if r.key == "nfr1"]
        return run, rec

    def test_a_session_that_ended_early_fails_the_gate(self):
        run, rec = self.flow(contract_from('[service]\nport = 8080\n' + NFR1))
        self.assertEqual(rec.status, "failed")
        self.assertIn("ended before the NFR-1 check", rec.reasons[0])
        self.assertEqual(run.result, "failed")

    def test_without_the_table_the_gate_is_skipped(self):
        _, rec = self.flow(config.Contract(port=8080))
        self.assertEqual(rec.status, "skipped")


if __name__ == "__main__":
    unittest.main()
