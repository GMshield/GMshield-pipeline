"""The end-to-end test with the fake model (Story 2.9): image selection, each container's arguments, the stand-in
Ollama over a real socket, the PDF, the outcome from result.json, where the stage runs, and the standalone folder.
Docker is replaced by a recorder; tests/fixtures/e2e holds copies of the three apps' contracts.
Run: python3 -m unittest -v"""
import contextlib
import http.client
import io
import importlib.util
import json
import math
import shutil
import subprocess
import tempfile
import threading
import types
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from gmshield_ci import config, dockerops, e2e, housekeeping, pipeline, stages

FIX = Path(__file__).parent / "fixtures" / "e2e"
RUN_ID = "20261120-120000-01234567"
SHAS = {"backend": "b" * 40, "frontend": "f" * 40, "worker": "a" * 40}
OWN_SHA = "c" * 40


def load_stand_in():
    spec = importlib.util.spec_from_file_location("stand_in_ollama", e2e.QUALITY / "stand_in_ollama.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_driver():
    """quality/e2e/driver.py, loaded by path; it imports Playwright only inside run()."""
    spec = importlib.util.spec_from_file_location("e2e_driver", e2e.QUALITY / "driver.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


class FakeDocker(dockerops.Docker):
    """Records `run` calls; the driver writes `result` (or nothing) to its /out mount and exits `driver_rc`."""
    def __init__(self, run_id=RUN_ID, result=None, driver_rc=0, rc=None):
        super().__init__("ci.slice", run_id, "inst")
        self.calls, self.result, self.driver_rc, self.rc = [], result, driver_rc, rc or {}

    def run(self, name, image, args, **kw):
        self.calls.append((name, image, args, kw))
        if name == "e2e-driver":
            out = next(h for h, c, _ in kw["mounts"] if c == "/out")
            cfg = json.loads((next(h for h, c, _ in kw["mounts"] if c == "/in") / "config.json").read_text())
            self.config = cfg
            Path(kw["log"]).write_text("driver output")
            if self.result is not None:
                Path(out, "result.json").write_text(json.dumps(self.result))
                if any(s["status"] == "failed" for s in self.result["steps"]):
                    Path(out, "ask-failed.png").write_bytes(b"png")
            return self.driver_rc
        return self.rc.get(name, 0)


def steps(failed_at=None, error="no reference listed"):
    out, seen = [], False
    for s in e2e.STEPS:
        if s == failed_at:
            out.append({"step": s, "status": "failed", "seconds": 1.0, "error": error})
            seen = True
        else:
            out.append({"step": s, "status": "not_run" if seen else "passed", "seconds": 1.0, "error": None})
    return {"steps": out, "passed": failed_at is None, "csp_violations": 0}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = self.tmp / "home"
        self.s = config.Settings(
            home=self.home, org="GMshield", branches=("develop", "main"), registry="localhost:5000",
            prod_network="gmshield-app", ci_slice="ci.slice",
            repos=[config.Repo(f"GMshield-{n}", f"file:///{n}") for n in ("backend", "frontend", "worker", "pipeline")],
            images={"zap": "zap@sha256:1", "postgres": "postgres@sha256:2", "redis": "redis@sha256:3",
                    "qdrant": "qdrant@sha256:4", "playwright": "playwright@sha256:5"},
            semgrep_rulesets=[], limits={"startup": 6}, gates={})
        self.images = set()
        self.cmds = []
        self.inspected = {}
        # mirrors with each app's contract (and the frontend's messages) committed; their heads are the "latest develop"
        self.heads = {}
        for svc in e2e.SERVICES:
            m = self.home / "mirrors" / f"GMshield-{svc}.git"
            (m / ".gmshield").mkdir(parents=True)
            shutil.copy(FIX / f"{svc}.toml", m / ".gmshield" / "pipeline.toml")
            if svc == "frontend":
                (m / "src" / "messages").mkdir(parents=True)
                (m / "src" / "messages" / "en.json").write_text("{}")
            git(m.parent, "init", "-q", str(m))
            git(m, "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
            git(m, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
            self.heads[svc] = git(m, "rev-parse", "HEAD")
        self.write_state({svc: self.heads[svc] for svc in e2e.SERVICES})
        self.images.add(e2e.driver_image(self.s))
        for mod in (e2e, stages):
            for name, fn in (("sh", self.fake_sh), ("capture", self.fake_capture),
                             ("container_logs", lambda n, dest: Path(dest).write_text("log"))):
                p = mock.patch.object(mod, name, fn)
                p.start()
                self.addCleanup(p.stop)
        p = mock.patch.object(e2e, "inspect", lambda obj, fmt: self.inspected.get(obj, {}).get(fmt, {
            "{{.State.Running}}": "true"}.get(fmt, "healthy")))
        p.start()
        self.addCleanup(p.stop)

    def write_state(self, shas: dict):
        (self.home / "state").mkdir(parents=True, exist_ok=True)
        (self.home / "state" / "state.json").write_text(json.dumps(
            {f"GMshield-{k}": {"develop": {"sha": v, "result": "failed"}, "main": {"sha": "x"}} for k, v in shas.items()}))
        self.images |= {f"gmshield-ci/{k}:{v}" for k, v in shas.items()}

    def fake_sh(self, cmd, log=None, timeout=600, env=None, cwd=None):
        self.cmds.append(cmd)
        return 0

    def fake_capture(self, cmd, timeout=120):
        self.cmds.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return (0, "sha256:x") if cmd[-1] in self.images else (1, "")
        if cmd[:2] == ["docker", "exec"]:
            return 0, "PONG" if "redis-cli" in cmd else "accepting connections"
        return 0, ""

    def session(self, docker=None, limit=1200):
        return e2e.Session(s=self.s, id=RUN_ID, docker=docker or FakeDocker(), dir=self.tmp / "out" / "e2e",
                           work=self.tmp / "work" / "e2e", rel="e2e/", log=lambda m: None,
                           deadline=e2e.time.monotonic() + limit)

    def own(self, svc="backend"):
        src = self.tmp / "own-src"
        e2e.gitops.export(self.home / "mirrors" / f"GMshield-{svc}.git", self.heads[svc], src)
        return e2e.App(svc, f"GMshield-{svc}", OWN_SHA, f"gmshield-ci/{svc}:{OWN_SHA}",
                       config.load_contract(src, f"GMshield-{svc}"), src)


class SelectionTest(Base):
    def test_own_image_and_the_others_latest_develop(self):
        apps = e2e.select_apps(self.session(), self.own("frontend"))
        self.assertEqual([a.service for a in apps], ["backend", "frontend", "worker"])
        by = {a.service: a for a in apps}
        self.assertEqual(by["frontend"].image, f"gmshield-ci/frontend:{OWN_SHA}")
        self.assertEqual(by["backend"].image, f"gmshield-ci/backend:{self.heads['backend']}")
        self.assertEqual(by["worker"].sha, self.heads["worker"])
        self.assertEqual(by["worker"].contract.service, "worker")          # read from the mirror at that commit
        self.assertEqual(by["backend"].contract.port, 8080)

    def test_latest_develop_whatever_its_result(self):
        self.assertEqual(e2e.latest_develop(self.s)["GMshield-worker"], self.heads["worker"])

    def test_missing_image_names_the_repo(self):
        self.images.discard(f"gmshield-ci/worker:{self.heads['worker']}")
        with self.assertRaisesRegex(e2e.E2EError, "no develop image of GMshield-worker; run its develop pipeline"):
            e2e.select_apps(self.session(), self.own("backend"))

    def test_no_develop_run_recorded(self):
        (self.home / "state" / "state.json").write_text("{}")
        with self.assertRaisesRegex(e2e.E2EError, "no develop image of GMshield-backend"):
            e2e.select_apps(self.session(), None)


class ArgsTest(Base):
    def apps(self):
        return {a.service: a for a in e2e.select_apps(self.session(), None)}

    def test_each_app_under_its_test_mode_name_on_the_run_network(self):
        sess, apps, net = self.session(), self.apps(), f"gmshield-ci-{RUN_ID}-e2e"
        for svc, alias in (("backend", "stand-in-backend"), ("frontend", "frontend"), ("worker", None)):
            argv = e2e.app_args(sess, apps[svc], net, None)
            self.assertEqual(argv[:4], ["docker", "run", "--name", f"gmshield-ci-{RUN_ID}-e2e-{svc}"])
            self.assertEqual(argv[argv.index("--network") + 1], net)
            self.assertIn(f"gmshield-ci.run={RUN_ID}", argv)
            self.assertIn("GMSHIELD_MODE=test", argv)
            self.assertNotIn("-p", argv)                                      # no host port
            self.assertEqual(argv[argv.index("--cgroup-parent") + 1], "ci.slice")
            self.assertEqual(argv[-1], apps[svc].image)
            if alias:
                self.assertEqual(argv[argv.index("--network-alias") + 1], alias)
            else:
                self.assertNotIn("--network-alias", argv)
        worker = e2e.app_args(sess, apps["worker"], net, None)
        self.assertIn("GMSHIELD_OLLAMA_URL=http://stand-in-ollama:11434", worker)    # not the production gateway
        self.assertNotIn("GMSHIELD_OLLAMA_URL=http://172.30.5.1:11434", worker)
        self.assertIn(f"gmshield-ci-{RUN_ID}-worker-work:/var/lib/gmshield-worker/work:rw", worker)
        self.assertEqual(worker[worker.index("--memory") + 1], "4352m")              # the contract's caps

    def test_dast_keeps_the_app_alias(self):
        c = self.apps()["frontend"].contract
        argv = config.container_args(c, self.s, "staging", name="n", image="i", network="net", run_id=RUN_ID)
        self.assertEqual(argv[argv.index("--network-alias") + 1], "app")

    def test_stand_ins_and_driver(self):
        sess, apps = self.session(), self.apps()
        q = e2e.qdrant_args(sess)
        self.assertEqual((q["image"], q["extra"][:2]), ("qdrant@sha256:4", ["--network-alias", "stand-in-qdrant"]))
        self.assertIn("/qdrant/storage", q["extra"])
        o = e2e.ollama_args(sess, apps["worker"])
        self.assertEqual((o["image"], o["entrypoint"]), (apps["worker"].image, "python"))
        self.assertEqual(o["args"][:2], ["-I", "/e2e/stand_in_ollama.py"])
        self.assertIn("stand-in-ollama", o["extra"])
        self.assertIn("--no-healthcheck", o["extra"])    # the worker image's check fails here; the server restarts unhealthy ones
        d = e2e.driver_args(sess, "front", self.tmp, self.tmp / "en.json")
        self.assertEqual((d["image"], d["network"]), (e2e.driver_image(self.s), "container:front"))
        self.assertRegex(d["image"], r"^gmshield-ci/e2e-driver:[0-9a-f]{12}$")
        self.assertIn((sess.dir, "/out", "rw"), d["mounts"])
        # an owner-only home of the run for Chromium, never the shared /tmp
        self.assertEqual(d["env"]["HOME"], stages.CONTAINER_HOME)
        self.assertIn((sess.work / "home" / "e2e-driver", stages.CONTAINER_HOME, "rw"), d["mounts"])
        self.assertEqual((sess.work / "home" / "e2e-driver").stat().st_mode & 0o777, 0o700)


class StandInOllamaTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_stand_in()
        quiet = type("Quiet", (self.mod.Handler,), {"log_message": lambda self, *a: None})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), quiet)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
        r = conn.getresponse()
        raw = r.read()
        conn.close()
        return r.status, json.loads(raw) if raw else None

    def test_embed_answers_one_deterministic_vector_per_input(self):
        status, body = self.call("POST", "/api/embed", {"model": "embeddinggemma:300m", "input": ["a b", "Lantern"],
                                                        "truncate": False})
        self.assertEqual(status, 200)
        v1, v2 = body["embeddings"]
        for v in (v1, v2):
            self.assertEqual(len(v), 768)
            self.assertTrue(all(isinstance(x, float) and math.isfinite(x) for x in v))
            self.assertGreater(sum(x * x for x in v), 0)
        self.assertNotEqual(v1, v2)
        _, again = self.call("POST", "/api/embed", {"input": ["a b", "Lantern"]})
        self.assertEqual(again["embeddings"], [v1, v2])

    def test_shared_words_make_closer_vectors(self):
        cos = lambda a, b: sum(x * y for x, y in zip(a, b)) / (sum(x * x for x in a) * sum(y * y for y in b)) ** .5
        _, body = self.call("POST", "/api/embed", {"input": [e2e.QUESTION, e2e.FACT, "The Bell of Low Tides rings."]})
        q, fact, other = body["embeddings"]
        self.assertGreater(cos(q, fact), cos(q, other))

    def test_other_requests_are_404(self):
        for method, path in (("GET", "/api/embed"), ("POST", "/api/chat"), ("GET", "/"), ("POST", "/api/embed/x")):
            self.assertEqual(self.call(method, path, {"input": ["x"]} if method == "POST" else None)[0], 404)

    def test_malformed_embed_is_refused(self):
        self.assertEqual(self.call("POST", "/api/embed", {"input": []})[0], 400)
        self.assertEqual(self.call("POST", "/api/embed", {"input": [1]})[0], 400)


class DriverStepsTest(unittest.TestCase):
    """The driver's step loop (run_steps), with a stand-in driver object instead of a browser."""
    def setUp(self):
        self.mod = load_driver()
        self.shots = []
        self.ran = []

    def fake(self, **behaviour):
        """A driver whose step methods record their call, then do what `behaviour` says (default: pass)."""
        ran, mod = self.ran, self.mod

        class Fake:
            csp: list
            deadline = 0.0

            def __init__(self):
                self.csp = []

        def method(step):
            def call(self):
                ran.append(step)
                what = behaviour.get(step)
                if what == "csp":
                    self.csp.append("enforce img-src http://elsewhere.test/x.png")
                elif isinstance(what, Exception):
                    raise what
            return call
        for step in mod.STEPS:
            setattr(Fake, step, method(step))
        return Fake()

    def run_steps(self, d):
        return self.mod.run_steps(d, self.mod.STEPS, self.mod.DEFAULT_LIMITS, e2e.time.monotonic() + 600,
                                  self.shots.append)

    def test_a_csp_violation_fails_its_step_and_stops_the_run(self):
        result = self.run_steps(self.fake(upload="csp"))
        statuses = [s["status"] for s in result["steps"]]
        self.assertEqual(statuses, ["passed", "failed", "not_run", "not_run", "not_run"])
        self.assertEqual(result["steps"][1]["error"],
                         "Content-Security-Policy violation: enforce img-src http://elsewhere.test/x.png")
        self.assertEqual((result["passed"], result["csp_violations"]), (False, 1))
        self.assertEqual(self.ran, ["sign_in", "upload"])
        self.assertEqual(self.shots, ["upload"])

    def test_a_failed_step_records_its_error_takes_a_screenshot_and_stops(self):
        result = self.run_steps(self.fake(ask=self.mod.StepFailed("1 reference(s), none to the uploaded material")))
        self.assertEqual([s["status"] for s in result["steps"]], ["passed"] * 3 + ["failed", "not_run"])
        self.assertEqual(result["steps"][3]["error"], "1 reference(s), none to the uploaded material")
        self.assertEqual(self.shots, ["ask"])
        self.assertEqual(self.ran, ["sign_in", "upload", "accept", "ask"])
        self.assertIsNone(result["steps"][4]["error"])
        self.assertFalse(result["passed"])

    def test_any_other_exception_names_its_type_and_a_failed_screenshot_is_ignored(self):
        def broken(step):
            raise RuntimeError("no page")
        result = self.mod.run_steps(self.fake(sign_in=TimeoutError("Timeout 3000ms exceeded.\nCall log: ...")),
                                    self.mod.STEPS, {}, e2e.time.monotonic() + 600, broken)
        self.assertEqual(result["steps"][0]["error"], "TimeoutError: Timeout 3000ms exceeded.")
        self.assertEqual([s["status"] for s in result["steps"]][1:], ["not_run"] * 4)

    def test_all_steps_passing(self):
        result = self.run_steps(self.fake())
        self.assertTrue(result["passed"])
        self.assertEqual([s["status"] for s in result["steps"]], ["passed"] * 5)
        self.assertEqual([s["step"] for s in result["steps"]], list(e2e.STEPS))
        self.assertEqual((self.shots, result["csp_violations"]), ([], 0))
        self.assertTrue(all(s["error"] is None for s in result["steps"]))


class PdfTest(unittest.TestCase):
    def test_two_pages_holding_the_fact(self):
        pdf = e2e.pdf_bytes()
        self.assertTrue(pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"/Count 2", pdf)
        self.assertIn(e2e.FACT.encode(), pdf)
        words = {w.strip("?.").lower() for w in e2e.QUESTION.split()}
        self.assertTrue({"lantern", "vessa", "starfire"} <= words)

    def test_parentheses_are_escaped(self):
        self.assertIn(rb"(a \(b\) c\\) Tj", e2e.text_pdf([["a (b) c\\"]]))


class OutcomeTest(Base):
    def run_stage(self, result, driver_rc=0, limit=1200):
        docker = FakeDocker(result=result, driver_rc=driver_rc)
        sess = self.session(docker, limit)
        out = e2e.execute(sess, self.own("backend"))
        return out, docker, sess

    def test_a_late_csp_violation_fails_a_run_whose_steps_passed(self):
        late = steps()
        late["csp_violations"] = 1
        self.assertEqual(e2e.judge(late, 0), ("error", "Content-Security-Policy violation"))
        (outcome, m, _, _), _, _ = self.run_stage(late)
        self.assertEqual((outcome, m["error"]), ("error", "Content-Security-Policy violation"))

    def test_judge(self):
        self.assertEqual(e2e.judge(steps(), 0), ("ok", "passed"))
        self.assertEqual(e2e.judge(steps("ask"), 1), ("error", "e2e step ask: no reference listed"))
        self.assertEqual(e2e.judge(None, 1), ("error", "the driver wrote no result.json (exit 1)"))
        self.assertEqual(e2e.judge(steps(), 124), ("error", "timed out"))
        partial = steps()
        partial["steps"][4]["status"] = "not_run"
        self.assertEqual(e2e.judge(partial, 0), ("error", "e2e step open_reference: not run"))

    def test_pass(self):
        (outcome, m, files, detail), docker, sess = self.run_stage(steps())
        self.assertEqual(outcome, "ok", detail)
        self.assertEqual(m["shas"], {"backend": OWN_SHA, "frontend": self.heads["frontend"],
                                     "worker": self.heads["worker"]})
        self.assertEqual([s["status"] for s in m["steps"]], ["passed"] * 5)
        self.assertIn("5/5 steps passed", detail)
        saved = json.loads((sess.dir / "result.json").read_text())
        self.assertEqual((saved["outcome"], saved["shas"]["backend"]), ("ok", OWN_SHA))
        for f in ("e2e/result.json", "e2e/driver.log", "e2e/e2e.log", "e2e/backend.log", "e2e/frontend.log",
                  "e2e/worker.log", "e2e/postgres.log", "e2e/redis.log", "e2e/stand-in-qdrant.log",
                  "e2e/stand-in-ollama.log"):
            self.assertIn(f, files)
        # the order, and the driver inside the frontend's network namespace
        names = [c[0] for c in docker.calls]
        self.assertEqual(names, ["e2e-postgres", "e2e-redis", "e2e-stand-in-qdrant", "e2e-stand-in-ollama",
                                 "e2e-probe", "e2e-probe", "probe", "probe", "e2e-driver"])
        driver = docker.calls[-1]
        self.assertEqual(driver[3]["network"], f"container:gmshield-ci-{RUN_ID}-e2e-frontend")
        self.assertEqual(docker.config["question"], e2e.QUESTION)
        runs = [c for c in self.cmds if c[:2] == ["docker", "run"]]
        self.assertEqual([r[3] for r in runs], [f"gmshield-ci-{RUN_ID}-e2e-{s}" for s in ("backend", "worker",
                                                                                          "frontend")])
        create = next(c for c in self.cmds if c[:3] == ["docker", "network", "create"])
        self.assertIn("--internal", create)
        self.assert_cleaned()

    def assert_cleaned(self):
        removed = [c for c in self.cmds if c[:4] == ["docker", "rm", "-f", "-v"]][-1]
        for n in ("backend", "frontend", "worker", "postgres", "redis", "stand-in-qdrant", "stand-in-ollama"):
            self.assertIn(f"gmshield-ci-{RUN_ID}-e2e-{n}", removed)
        self.assertIn(["docker", "network", "rm", f"gmshield-ci-{RUN_ID}-e2e"], self.cmds)
        vols = [c for c in self.cmds if c[:4] == ["docker", "volume", "rm", "-f"]][-1]
        self.assertIn(f"gmshield-ci-{RUN_ID}-backend-files", vols)
        self.assertIn(f"gmshield-ci-{RUN_ID}-worker-work", vols)

    def test_driver_image_built_once_when_missing(self):
        tag = e2e.driver_image(self.s)
        self.images.discard(tag)
        self.assertIsNone(e2e.build_driver(self.session()))
        build = [c for c in self.cmds if c[:3] == ["docker", "buildx", "build"]]
        self.assertEqual(len(build), 1)
        self.assertIn("PLAYWRIGHT_IMAGE=playwright@sha256:5", build[0])
        self.assertEqual((build[0][build[0].index("-t") + 1], build[0][-1]), (tag, str(e2e.QUALITY)))
        self.assertEqual(build[0][build[0].index("--cgroup-parent") + 1], "ci.slice")
        self.assertFalse(any(x.startswith("gmshield-ci.run=") for x in build[0]))     # kept between runs
        self.images.add(tag)
        self.cmds.clear()
        self.assertIsNone(e2e.build_driver(self.session()))
        self.assertFalse([c for c in self.cmds if c[:3] == ["docker", "buildx", "build"]])

    def test_driver_image_build_failure_is_a_stage_error(self):
        self.images.discard(e2e.driver_image(self.s))
        with mock.patch.object(e2e, "sh", lambda cmd, *a, **k: 1 if cmd[:3] == ["docker", "buildx", "build"] else 0):
            outcome, m, files, _ = e2e.stage(self.run_like())
        self.assertEqual((outcome, m["error"]), ("error", "the driver image failed to build (exit 1)"))
        self.assertIn("e2e/e2e.log", files)

    def run_like(self, docker=None):
        own = self.own("backend")
        return types.SimpleNamespace(
            contract=own.contract, image_built=True, s=self.s, id=RUN_ID, docker=docker or FakeDocker(result=steps()),
            dir=self.tmp / "run", work=self.tmp / "run-work", log=lambda m: None,
            repo=types.SimpleNamespace(name="GMshield-backend"), sha=OWN_SHA,
            local_image=f"gmshield-ci/backend:{OWN_SHA}", src=own.src)

    def test_stage_runs_the_run_image_with_the_others(self):
        run = self.run_like()
        outcome, m, files, detail = e2e.stage(run)
        self.assertEqual(outcome, "ok", detail)
        self.assertIn("e2e/result.json", files)
        self.assertTrue((run.dir / "e2e" / "result.json").is_file())
        self.assertEqual(m["shas"]["backend"], run.sha)
        saved = json.loads((run.dir / "e2e" / "result.json").read_text())
        self.assertEqual(saved["images"]["backend"], run.local_image)
        backend = next(c for c in self.cmds if c[:2] == ["docker", "run"] and c[3].endswith("-e2e-backend"))
        self.assertEqual(backend[-1], run.local_image)

    def test_the_deadline_starts_after_the_driver_image(self):
        seen = {}

        def slow_build(sess, log):
            e2e.time.sleep(0.3)
            seen["built"] = e2e.time.monotonic()
            return "tag"

        def capture_deadline(sess, own):
            seen["deadline"] = sess.deadline
            return "ok", {}, [], "d"
        with mock.patch.object(e2e, "ensure_driver_image", slow_build), mock.patch.object(e2e, "execute", capture_deadline):
            e2e.stage(self.run_like())
        self.assertGreaterEqual(seen["deadline"], seen["built"] + e2e.DEFAULT_LIMIT)

    def test_worker_not_running_stops_before_the_browser(self):
        self.inspected[f"gmshield-ci-{RUN_ID}-e2e-worker"] = {"{{.State.Running}}": "false"}
        docker = FakeDocker(result=steps())
        outcome, m, files, _ = e2e.execute(self.session(docker), self.own("backend"))
        self.assertEqual(outcome, "error")
        self.assertIn("the worker was not healthy", m["error"])
        self.assertNotIn("e2e-driver", [c[0] for c in docker.calls])
        self.assertIn("e2e/worker.log", files)

    def test_stand_in_qdrant_not_ready_starts_no_app(self):
        docker = FakeDocker(result=steps(), rc={"e2e-probe": 1})
        outcome, m, _, _ = e2e.execute(self.session(docker), self.own("backend"))
        self.assertEqual((outcome, m["error"]), ("error", "the stand-in Qdrant did not become ready"))
        self.assertFalse([c for c in self.cmds if c[:2] == ["docker", "run"]])
        self.assertNotIn("e2e-driver", [c[0] for c in docker.calls])
        removed = [c for c in self.cmds if c[:4] == ["docker", "rm", "-f", "-v"]][-1]
        self.assertIn(f"gmshield-ci-{RUN_ID}-e2e-stand-in-qdrant", removed)
        self.assertIn(["docker", "network", "rm", f"gmshield-ci-{RUN_ID}-e2e"], self.cmds)

    def test_driver_image_changes_with_its_inputs(self):
        other = config.Settings(**{**self.s.__dict__, "images": {**self.s.images, "playwright": "playwright@sha256:6"}})
        self.assertNotEqual(e2e.driver_image(self.s), e2e.driver_image(other))

    def test_step_failure(self):
        (outcome, m, files, detail), _, _ = self.run_stage(steps("ask"), driver_rc=1)
        self.assertEqual(outcome, "error")
        self.assertEqual(m["error"], "e2e step ask: no reference listed")
        self.assertEqual([s["status"] for s in m["steps"]], ["passed"] * 3 + ["failed", "not_run"])
        self.assertIn("e2e/ask-failed.png", files)
        self.assert_cleaned()

    def test_missing_result(self):
        (outcome, m, _, _), _, sess = self.run_stage(None, driver_rc=1)
        self.assertEqual((outcome, m["error"]), ("error", "the driver wrote no result.json (exit 1)"))
        saved = json.loads((sess.dir / "result.json").read_text())
        self.assertEqual([s["status"] for s in saved["steps"]], ["not_run"] * 5)

    def test_driver_timeout(self):
        (outcome, m, _, _), _, _ = self.run_stage(None, driver_rc=124)
        self.assertEqual((outcome, m["error"]), ("error", "timed out"))
        self.assert_cleaned()

    def test_over_the_stage_limit_before_the_browser(self):
        (outcome, m, _, _), docker, _ = self.run_stage(steps(), limit=0)
        self.assertEqual((outcome, m["error"]), ("error", "timed out"))
        self.assertNotIn("e2e-driver", [c[0] for c in docker.calls])

    def test_app_not_healthy(self):
        docker = FakeDocker(result=steps(), rc={"probe": 1})
        (outcome, m, files, _) = e2e.execute(self.session(docker), self.own("backend"))
        self.assertEqual(outcome, "error")
        self.assertIn("the backend was not healthy at /actuator/health", m["error"])
        self.assertIn("e2e/backend.log", files)
        self.assertNotIn("e2e-driver", [c[0] for c in docker.calls])

    def test_other_repo_without_image(self):
        self.images.discard(f"gmshield-ci/frontend:{self.heads['frontend']}")
        (outcome, m, _, _), docker, _ = self.run_stage(steps())
        self.assertEqual((outcome, m["error"]), ("error", "no develop image of GMshield-frontend; run its develop pipeline"))
        self.assertEqual(docker.calls, [])

    def test_stage_skips_without_image_and_outside_the_apps(self):
        run = types.SimpleNamespace(contract=types.SimpleNamespace(service="backend"), image_built=False)
        self.assertEqual(e2e.stage(run)[0], "skipped")
        run = types.SimpleNamespace(contract=types.SimpleNamespace(service="pipeline"), image_built=True)
        self.assertEqual(e2e.stage(run)[0], "skipped")


class WhereTest(unittest.TestCase):
    def flow(self, service, mode="full"):
        order = []
        run = types.SimpleNamespace(mode=mode, old=None, sha="s", records=[], notes=[], id=RUN_ID, tree="t",
                                    repo=types.SimpleNamespace(name=f"GMshield-{service}"),
                                    contract=types.SimpleNamespace(service=service),
                                    s=types.SimpleNamespace(state_dir=Path(tempfile.mkdtemp())))
        self.addCleanup(shutil.rmtree, run.s.state_dir, ignore_errors=True)
        with mock.patch.object(pipeline, "_source_checks", lambda *a, **k: None), \
                mock.patch.object(pipeline.stages, "execute",
                                  lambda run, key, title, gate, fn, *a: order.append((key, gate, fn)) or []):
            pipeline.develop_flow(run)
        return order

    def test_full_develop_runs_of_the_three_apps_end_with_it_without_a_gate(self):
        for svc in ("backend", "frontend", "worker"):
            order = self.flow(svc)
            self.assertEqual([k for k, _, _ in order],
                             ["sonar", "image", "integration_tests", "dast", "nfr1", "e2e", "leak"])
            self.assertEqual(order[-2][1:], (None, e2e.stage))      # the SM-1 leak test follows (tests/test_leak.py)

    def test_not_in_light_runs_or_the_pipeline_own_runs(self):
        self.assertEqual(self.flow("backend", mode="light"), [])
        self.assertNotIn("e2e", [k for k, _, _ in self.flow("pipeline")])

    def test_not_on_main(self):
        import inspect
        self.assertNotIn("e2e", inspect.getsource(pipeline.main_flow))

    def test_a_failed_e2e_fails_the_run(self):
        run = types.SimpleNamespace(s=types.SimpleNamespace(gates={}), titles={}, lock=threading.Lock(), records=[],
                                    log=lambda m: None)
        [r] = stages.execute(run, "e2e", e2e.TITLE, None, lambda run: ("error", {"error": "e2e step ask: x"}, [], "x"))
        self.assertEqual((r.status, r.reasons), ("failed", ["e2e step ask: x"]))
        self.assertFalse(pipeline._passed(run))


class StandaloneTest(unittest.TestCase):
    def test_refused_while_a_run_holds_the_poll_lock(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        s = config.Settings(home=tmp, org="o", branches=("develop",), registry="r", prod_network="p",
                            ci_slice="ci.slice", repos=[], images={}, semgrep_rulesets=[], limits={}, gates={})

        def must_not_run(*a, **k):
            raise AssertionError("the test ran while a pipeline run held the lock")
        with pipeline.single_instance(s) as ok, \
                mock.patch.object(e2e, "execute", must_not_run), \
                mock.patch.object(e2e, "ensure_driver_image", must_not_run), \
                contextlib.redirect_stdout(io.StringIO()) as said:
            self.assertTrue(ok)
            self.assertEqual(e2e.standalone(s), 1)
        self.assertIn("a pipeline run is in progress", said.getvalue())

    def test_folder_name_never_matches_a_run_id(self):
        name = e2e.folder_name(datetime(2026, 11, 20, 12, 34, 56, tzinfo=timezone.utc))
        self.assertEqual(name, "2026-11-20-123456")
        self.assertIsNone(housekeeping.RUN_ID.match(name))
        self.assertIsNotNone(housekeeping.RUN_ID.match(RUN_ID))

    def test_standalone_cleans_up_and_exits_by_outcome(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        s = config.Settings(home=tmp, org="o", branches=("develop",), registry="r", prod_network="p",
                            ci_slice="ci.slice", repos=[], images={}, semgrep_rulesets=[], limits={}, gates={})
        cleaned = []
        for outcome, rc in (("ok", 0), ("error", 1)):
            with mock.patch.object(e2e, "execute", lambda sess, own: (outcome, {"steps": []}, [], "d")), \
                    mock.patch.object(e2e, "ensure_driver_image", lambda sess, log: "tag"), \
                    mock.patch.object(e2e.Docker, "cleanup", lambda self: cleaned.append(self.label)), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(e2e.standalone(s), rc)
        self.assertTrue(all(label.startswith("gmshield-ci.run=e2e-") for label in cleaned))
        self.assertEqual(len(cleaned), 2)


if __name__ == "__main__":
    unittest.main()
