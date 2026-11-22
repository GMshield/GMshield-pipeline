"""The SM-1 leak gate with the fake model (Story 3.13, part A): the fixed question set and library, the runner against
a stub backend (tests/fixtures/sm1/stub.py), each row of the story's matrix from recorded runner output, Postgres rows
and worker log lines, the stage on its own stack (Docker replaced by a recorder, as tests/test_e2e.py does), where the
stage runs, and the standalone folder. No answer or passage text may reach the record or the results.
Run: python3 -m unittest -v"""
import contextlib
import copy
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import threading
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from gmshield_ci import config, dashboard, e2e, housekeeping, leak, pipeline, stages
from tests.test_e2e import OWN_SHA, RUN_ID, Base, FakeDocker

STUB_PATH = Path(__file__).resolve().parent / "fixtures" / "sm1" / "stub.py"
_spec = importlib.util.spec_from_file_location("sm1_stub", STUB_PATH)
stub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stub)


def load_runner():
    spec = importlib.util.spec_from_file_location("sm1_runner", leak.QUALITY / "runner.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod                  # its dataclasses look their module up
    spec.loader.exec_module(mod)
    return mod


runner = load_runner()
QUESTIONS = leak.questions()
SECRETS = ("ANSWER-SECRET", "NAME-SECRET")


def record_run(tmp: Path, **behaviour):
    """One runner run against the stub: (exit code, record, passages, turns, worker log, the stub's state)."""
    tmp.mkdir(parents=True, exist_ok=True)
    with stub.Backend(**behaviour) as backend:
        cfg = leak.runner_config(600)
        cfg.update({"base": backend.base, "questions": str(leak.QUESTIONS), "out": str(tmp / "runner.json"),
                    "limits": {"question": 10, "material": 10, "indexing": 10, "poll": 0.001}})
        for m in cfg["materials"]:
            src = next(x for x in leak.MATERIALS if x["key"] == m["key"])
            (tmp / m["filename"]).write_bytes(leak.library_pdf(src["source"]))
            m["file"] = str(tmp / m["filename"])
        (tmp / "config.json").write_text(json.dumps(cfg))
        with contextlib.redirect_stderr(io.StringIO()):
            rc = runner.main(["runner.py", str(tmp / "config.json")])
        rec = json.loads((tmp / "runner.json").read_text())
        return rc, rec, backend.passages(), backend.turns(), backend.worker_log(), backend.state


class Recorded(unittest.TestCase):
    """A clean run, recorded once from the stub; tests change copies of it."""
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.rc, cls.rec, cls.passages, cls.turns, cls.log, cls.state = record_run(cls.tmp / "clean")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def judge(self, rec=None, passages=None, turns=None, log=None, **kw):
        return leak.judge(copy.deepcopy(rec if rec is not None else self.rec),
                          passages if passages is not None else self.passages,
                          turns if turns is not None else self.turns,
                          leak.found_ids(log if log is not None else self.log), **kw)

    def ids_of(self, key: str) -> list[str]:
        version = self.rec["materials"][key]["versionId"]
        return sorted(p for p, v in self.passages.items() if v == version)

    def turn(self, rec, campaign: str, qid: str, phase: str = "main") -> dict:
        return next(t for t in rec["turns"] if (t["campaign"], t["question"], t["phase"]) == (campaign, qid, phase))

    def log_line(self, job: str, ids: list[str]) -> str:
        return ("2026-11-22T12:00:01.000000000Z " + json.dumps({"event": "retrieval.search_done", "jobId": job,
                                                                 "ids": ids, "level": "INFO"}) + "\n")


# ------------------------------------------------------------------ the fixed set

class QuestionSetTest(unittest.TestCase):
    def test_shape(self):
        self.assertEqual(len(QUESTIONS), 40)
        self.assertEqual(sorted({q["language"] for q in QUESTIONS}), ["en", "pt-BR"])
        self.assertEqual(sum(q["language"] == "pt-BR" for q in QUESTIONS), 20)
        self.assertEqual(sum(q["language"] == "en" for q in QUESTIONS), 20)
        self.assertGreaterEqual(sum(q["kind"] == "house" for q in QUESTIONS), 20)
        self.assertEqual({q["kind"] for q in QUESTIONS}, {"house", "notes", "neutral"})
        self.assertEqual(len({q["id"] for q in QUESTIONS}), 40)
        for q in QUESTIONS:
            self.assertTrue(q["id"] and q["topic"] and q["question"].strip(), q)
            self.assertLessEqual(len(q["question"]), 4000)

    def test_each_house_question_names_a_marker_of_the_house_rules(self):
        house = (leak.LIBRARY / "HA.txt").read_text(encoding="utf-8")
        rules = (leak.LIBRARY / "R.txt").read_text(encoding="utf-8") + (leak.LIBRARY / "NB.txt").read_text("utf-8")
        markers = {q["marker"] for q in QUESTIONS if q["kind"] == "house"}
        self.assertEqual(len(markers), 6)
        for marker in markers:
            self.assertIn(f"(regra {marker})", house)
            self.assertNotIn(marker, rules)                   # only the house rules carry them

    def test_control_is_a_house_question_of_the_set(self):
        q = next(q for q in QUESTIONS if q["id"] == leak.CONTROL["question"])
        self.assertEqual(q["kind"], "house")
        self.assertEqual(leak.CONTROL["campaign"], "livro")

    def test_library_files_fit_their_pdf_pages(self):
        self.assertEqual(sorted(p.name for p in leak.LIBRARY.iterdir()), ["HA.txt", "NB.txt", "R.txt", "X.txt"])
        for m in leak.MATERIALS:
            pages = leak.pages(m["source"])
            self.assertTrue(pages)
            for page in pages:
                self.assertLessEqual(len(page), 50)
                for line in page:
                    self.assertLessEqual(len(line), 80, line)
                    line.encode("latin-1")                     # WinAnsiEncoding reads it as Latin-1
            pdf = leak.library_pdf(m["source"])
            self.assertTrue(pdf.startswith(b"%PDF-1.4"))
            self.assertIn(b"/Encoding /WinAnsiEncoding", pdf)
            self.assertIn(b"/Count %d" % len(pages), pdf)
        self.assertEqual(len(leak.pages("R.txt")), 2)
        self.assertIn("Capítulo 1: Testes e combate".encode("latin-1"), leak.library_pdf("R.txt"))

    def test_scopes_allowed(self):
        self.assertEqual(leak.ALLOWED, {"casa": ("R", "HA"), "livro": ("R", "NB")})
        places = {m["key"]: m.get("campaign") or m.get("system") for m in leak.MATERIALS}
        self.assertEqual(places, {"R": "vale", "HA": "casa", "NB": "livro", "X": "mar"})


# ------------------------------------------------------------------ the runner against the stub

class RunnerTest(Recorded):
    def test_clean_run_records_every_turn_and_the_control(self):
        self.assertEqual(self.rc, 0)
        self.assertIsNone(self.rec["error"])
        self.assertEqual(self.rec["phase"], "complete")
        main = [t for t in self.rec["turns"] if t["phase"] == "main"]
        self.assertEqual(len(main), 80)
        self.assertEqual({(t["campaign"], t["question"]) for t in main},
                         {(c, q["id"]) for c in ("casa", "livro") for q in QUESTIONS})
        self.assertTrue(all(t["ended"] == "done" and t["turnId"] and t["lastEventId"] for t in main))
        [ctl] = [t for t in self.rec["turns"] if t["phase"] == "control"]
        self.assertEqual((ctl["campaign"], ctl["question"]), ("livro", "q01"))
        self.assertEqual(self.rec["control"]["otherTierOff"], True)
        self.assertEqual((self.rec["control"]["scopeVersionOn"], self.rec["control"]["scopeVersionOff"]), (1, 2))
        self.assertEqual(sorted(self.rec["materials"]), ["HA", "NB", "R", "X"])
        for key in ("casa", "livro"):
            self.assertEqual(self.rec["scopes"][key]["version"], 0)
        # one at a time, one new questions conversation each, every call with the test-mode credential
        self.assertEqual(self.state.unauthorized, 0)
        self.assertEqual(len({t["conversationId"] for t in self.rec["turns"]}), 81)

    def test_each_material_in_its_place(self):
        st = self.state
        sys_ids = {v: k for k, v in self.rec["systems"].items()}
        camp_ids = {v: k for k, v in self.rec["campaigns"].items()}
        places = {}
        for m in st.materials.values():
            places[m["key"]] = camp_ids.get(m.get("campaign")) or sys_ids.get((m.get("systems") or [None])[0])
        self.assertEqual(places, {"vale-de-ferro-regras.pdf": "vale", "casa-regras-da-casa.pdf": "casa",
                                  "livro-notas-de-sessao.pdf": "livro", "mar-de-cinzas-regras.pdf": "mar"})
        self.assertEqual({c["name"] for c in st.campaigns.values()}, {"Casa", "Livro"})
        self.assertTrue(all(c["system"] == self.rec["systems"]["vale"] for c in st.campaigns.values()))

    def test_no_text_reaches_the_record(self):
        text = (self.tmp / "clean" / "runner.json").read_text()
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        for q in QUESTIONS:
            self.assertNotIn(q["question"], text)
        self.assertNotIn("Vale de Ferro", text)

    def test_the_session_is_renewed_when_due(self):
        rc, rec, *_ , st = record_run(self.tmp / "renew", renew_after=0)
        self.assertEqual(rc, 0)
        self.assertGreater(st.renewals, 10)
        self.assertEqual(st.unauthorized, 0)

    def test_a_stop_is_recorded_with_its_phase(self):
        with stub.Backend() as backend:
            cfg = {**leak.runner_config(60), "base": backend.base, "code": "stand-in.x.other@example.test",
                   "out": str(self.tmp / "refused.json"), "questions": str(leak.QUESTIONS)}
            (self.tmp / "refused-config.json").write_text(json.dumps(cfg))
            with contextlib.redirect_stderr(io.StringIO()):
                rc = runner.main(["runner.py", str(self.tmp / "refused-config.json")])
        rec = json.loads((self.tmp / "refused.json").read_text())
        self.assertEqual(rc, 2)
        self.assertEqual(rec["error"], "sign_in: sign-in callback: sign_in.refused")

    def test_the_clean_run_passes(self):
        result = self.judge()
        self.assertEqual((result["verdict"], result["reason"]), ("passed", "80/80 clean, control ok"))
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["campaigns"]["Casa"]["cited"], {"R": 40, "HA": 40})
        self.assertEqual(result["campaigns"]["Livro"]["cited"], {"R": 40, "NB": 40})
        self.assertEqual(result["control"]["status"], "ok")
        self.assertEqual(result["control"]["foundHouseRules"], 2)
        self.assertEqual({k: m["passages"] for k, m in result["materials"].items()},
                         {"R": 2, "HA": 2, "NB": 2, "X": 2})


# ------------------------------------------------------------------ the matrix

class MatrixTest(Recorded):
    def test_found_leak(self):
        _, rec, passages, turns, log, _ = record_run(self.tmp / "found", leak="casa-regras", found_only=True)
        result = leak.judge(rec, passages, turns, leak.found_ids(log))
        self.assertEqual(result["verdict"], "failed")
        ha = sorted(p for p, v in passages.items() if v == rec["materials"]["HA"]["versionId"])
        self.assertEqual(result["reason"], f"leak found: Livro q01 HA:{ha[0]}, HA:{ha[1]}")
        self.assertEqual({f["check"] for f in result["failures"]}, {"found"})
        self.assertEqual(sum(1 for f in result["failures"] if f["check"] == "found"), 40)

    def test_cited_leak(self):
        rec = copy.deepcopy(self.rec)
        ha = self.ids_of("HA")
        self.turn(rec, "livro", "q07")["references"].append([ha[0]])
        result = self.judge(rec)
        self.assertEqual((result["verdict"], result["reason"]), ("failed", f"leak cited: Livro q07 HA:{ha[0]}"))
        rec = copy.deepcopy(self.rec)
        self.turn(rec, "casa", "q33")["citations"].append(self.ids_of("X")[1])
        self.assertEqual(self.judge(rec)["reason"], f"leak cited: Casa q33 X:{self.ids_of('X')[1]}")

    def test_found_and_cited_leak_both_named(self):
        _, rec, passages, turns, log, _ = record_run(self.tmp / "both", leak="casa-regras")
        result = leak.judge(rec, passages, turns, leak.found_ids(log))
        self.assertTrue(result["reason"].startswith("leak found: Livro q01 HA:"))
        self.assertEqual({f["check"] for f in result["failures"]}, {"found", "cited"})

    def test_refused_by_the_backend_is_a_found_leak(self):
        rec = copy.deepcopy(self.rec)
        t = self.turn(rec, "livro", "q12")
        t.update(ended="error", error="scope.passage_refused", citations=[], references=[])
        result = self.judge(rec)
        self.assertEqual((result["verdict"], result["reason"]),
                         ("failed", "leak found: Livro q12 scope.passage_refused"))

    def test_other_error_or_timeout(self):
        rec = copy.deepcopy(self.rec)
        self.turn(rec, "livro", "q05").update(ended="error", error="model.unavailable")
        self.assertEqual(self.judge(rec)["reason"], "q05 Livro: model.unavailable")
        rec = copy.deepcopy(self.rec)
        self.turn(rec, "casa", "q30").update(ended="timeout", error="timeout")
        self.assertEqual(self.judge(rec)["reason"], "q30 Casa: timeout")
        rec = copy.deepcopy(self.rec)
        self.turn(rec, "casa", "q02")["stopped"] = True
        self.assertEqual(self.judge(rec)["reason"], "q02 Casa: stopped")
        rec = copy.deepcopy(self.rec)
        self.turn(rec, "casa", "q02").update(turnId=None, ended="ask", error="ask:http.500")
        self.assertEqual(self.judge(rec)["reason"], "q02 Casa: ask:http.500")

    def test_empty_retrieval_is_not_exercised(self):
        ha = set(self.ids_of("HA"))
        rec = copy.deepcopy(self.rec)
        t = self.turn(rec, "casa", "q04")
        t["citations"] = [p for p in t["citations"] if p not in ha]
        t["references"] = [[p for p in r if p not in ha] for r in t["references"]]
        result = self.judge(rec)
        self.assertEqual((result["verdict"], result["reason"]), ("failed", "not exercised: Casa q04 does not cite HA"))
        rec = copy.deepcopy(self.rec)
        nb = set(self.ids_of("NB"))
        for t in rec["turns"]:
            if t["campaign"] == "livro" and t["phase"] == "main":
                t["citations"] = [p for p in t["citations"] if p not in nb]
                t["references"] = [[p for p in r if p not in nb] for r in t["references"]]
        self.assertEqual(self.judge(rec)["reason"], "not exercised: Livro never cites NB")

    def test_a_turn_with_no_retrieval_record_is_not_exercised(self):
        job = self.turns[self.turn(self.rec, "livro", "q20")["turnId"]]["job"]
        log = "\n".join(l for l in self.log.splitlines() if job not in l)
        self.assertEqual(self.judge(log=log)["reason"], "not exercised: Livro q20 no retrieval record")

    def test_blind_check(self):
        ctl = self.turn(self.rec, "livro", "q01", "control")
        job = self.turns[ctl["turnId"]]["job"]
        ha = set(self.ids_of("HA"))
        lines = []
        for line in self.log.splitlines():
            if job in line:
                d = json.loads(line[line.index("{"):])
                d["ids"] = [p for p in d["ids"] if p not in ha]
                line = json.dumps(d)
            lines.append(line)
        result = self.judge(log="\n".join(lines))
        self.assertEqual((result["verdict"], result["reason"]),
                         ("error", "control failed: the check cannot see a leak"))
        self.assertEqual(result["control"]["foundHouseRules"], 0)

    def test_the_control_tier_left_on_is_an_error(self):
        rec = copy.deepcopy(self.rec)
        rec["control"]["otherTierOff"] = False
        self.assertEqual(self.judge(rec)["reason"], "the other tier was not turned off again")

    def test_runner_stopped_or_missing(self):
        # stopped at question 16 in Livro: Postgres and the worker hold the turns made until then, no more
        rec = copy.deepcopy(self.rec)
        rec["turns"] = rec["turns"][:30]
        rec["error"], rec["phase"] = "questions: timed out", "questions"
        made = {t["turnId"] for t in rec["turns"]}
        turns = {t: d for t, d in self.turns.items() if t in made}
        log = "\n".join(l for l in self.log.splitlines() if any(d["job"] in l for d in turns.values()))
        result = self.judge(rec, turns=turns, log=log)
        self.assertEqual((result["verdict"], result["reason"]), ("error", "the runner stopped at questions: timed out"))
        self.assertEqual(leak.judge(None, {}, {}, {}, rc=1)["reason"], "the runner wrote no record (exit 1)")
        self.assertEqual(leak.judge(None, {}, {}, {}, rc=124)["reason"], "timed out")
        rec = copy.deepcopy(self.rec)
        rec["turns"] = [t for t in rec["turns"] if not (t["campaign"] == "casa" and t["question"] == "q40")]
        self.assertEqual(self.judge(rec)["reason"], "only 79/80 questions asked")

    def test_a_turn_never_posted_leaves_the_runner_error(self):
        # the run stopped (its time ran out) after appending question 16's Casa turn and before posting it
        rec = copy.deepcopy(self.rec)
        rec["turns"] = rec["turns"][:30]
        made = {t["turnId"] for t in rec["turns"]}
        rec["turns"].append(runner.Turn("main", "casa", "q16", "notes", 0).record())
        rec["error"], rec["phase"] = "questions: timed out", "questions"
        turns = {t: d for t, d in self.turns.items() if t in made}
        log = "\n".join(l for l in self.log.splitlines() if any(d["job"] in l for d in turns.values()))
        result = self.judge(rec, turns=turns, log=log)
        self.assertEqual((result["verdict"], result["reason"]), ("error", "the runner stopped at questions: timed out"))
        self.assertEqual(result["turns"], 30)

    def test_the_broken_check_names_the_found_and_cited_house_rule_ids(self):
        broken = {"casa": ("R",), "livro": ("R", "NB")}
        result = self.judge(allowed=broken)
        ha = self.ids_of("HA")
        self.assertEqual((result["verdict"], result["reason"]),
                         ("failed", f"leak found: Casa q01 HA:{ha[0]}, HA:{ha[1]}"))
        cited = [f for f in result["failures"] if f["check"] == "cited"]
        self.assertEqual(len(cited), 40)
        self.assertEqual([x["id"] for x in cited[0]["foreign"]], ha)
        self.assertTrue(all(x["material"] == "HA" for f in cited for x in f["foreign"]))


class EventsTest(Recorded):
    """The runner's record of each event, from the stub's streams, as the gate judges it."""
    def by_text(self, qid: str) -> str:
        return next(q["question"] for q in QUESTIONS if q["id"] == qid)

    def test_an_id_sent_only_as_a_citation_is_a_cited_leak(self):
        _, rec, passages, turns, log, _ = record_run(self.tmp / "cite-only", cite_only="mar-de-cinzas")
        x = sorted(p for p, v in passages.items() if v == rec["materials"]["X"]["versionId"])
        t = self.turn(rec, "livro", "q01")
        self.assertTrue(set(x) <= set(t["citations"]))
        self.assertFalse(set(x) & {p for ref in t["references"] for p in ref})
        result = leak.judge(rec, passages, turns, leak.found_ids(log))
        self.assertEqual((result["verdict"], result["reason"]), ("failed", f"leak cited: Livro q01 X:{x[0]}, X:{x[1]}"))
        self.assertNotIn("found", {f["check"] for f in result["failures"]})

    def test_a_refused_passage_is_recorded_and_found(self):
        _, rec, passages, turns, log, _ = record_run(
            self.tmp / "refused", error={self.by_text("q12"): "scope.passage_refused"})
        t = self.turn(rec, "casa", "q12")
        self.assertEqual((t["ended"], t["error"]), ("error", "scope.passage_refused"))
        result = leak.judge(rec, passages, turns, leak.found_ids(log))
        self.assertEqual((result["verdict"], result["reason"]),
                         ("failed", "leak found: Casa q12 scope.passage_refused"))

    def test_a_stopped_answer_is_recorded_and_fails(self):
        _, rec, passages, turns, log, _ = record_run(self.tmp / "stopped", stopped={self.by_text("q05")})
        t = self.turn(rec, "casa", "q05")
        self.assertEqual((t["ended"], t["stopped"]), ("done", True))
        result = leak.judge(rec, passages, turns, leak.found_ids(log))
        self.assertEqual((result["verdict"], result["reason"]), ("failed", "q05 Casa: stopped"))


class MappingTest(Recorded):
    def test_jobs_map_to_campaigns_through_postgres(self):
        # a Casa job's found line holding an NB id is a Casa leak, whatever the runner's record says
        t = self.turn(self.rec, "casa", "q14")
        job = self.turns[t["turnId"]]["job"]
        nb = self.ids_of("NB")[0]
        result = self.judge(log=self.log + self.log_line(job, [nb]))
        self.assertEqual(result["reason"], f"leak found: Casa q14 NB:{nb}")
        # the same line under a Livro job is clean
        t = self.turn(self.rec, "livro", "q14")
        job = self.turns[t["turnId"]]["job"]
        self.assertEqual(self.judge(log=self.log + self.log_line(job, [nb]))["verdict"], "passed")

    def test_a_job_of_no_turn_is_a_found_leak(self):
        result = self.judge(log=self.log + self.log_line("00000000-0000-0000-0000-000000000009", [self.ids_of("R")[0]]))
        self.assertTrue(result["reason"].startswith("leak found: job 00000000-0000-0000-0000-000000000009 of no turn"))

    def test_a_turn_postgres_puts_in_the_other_campaign(self):
        turns = copy.deepcopy(self.turns)
        tid = self.turn(self.rec, "casa", "q17")["turnId"]
        turns[tid]["campaign"] = self.rec["campaigns"]["livro"]
        result = self.judge(turns=turns)
        self.assertEqual(result["verdict"], "failed")
        self.assertIn({"check": "ended", "campaign": "Casa", "question": "q17", "code": "turn.other_campaign"},
                      result["failures"])

    def test_the_control_is_judged_apart(self):
        # with Livro's other tier on, its control job finds HA and X: no leak, and the control passes
        result = self.judge()
        self.assertEqual(result["turns"], 80)
        self.assertFalse(any(f.get("question") == "q01" and f["campaign"] == "Livro" for f in result["failures"]))

    def test_found_ids_reads_timestamped_lines_and_every_attempt(self):
        log = ("2026-11-22T12:00:00Z " + json.dumps({"event": "retrieval.search_done", "jobId": "j", "ids": ["a"]})
               + "\nnot json {\n" + json.dumps({"event": "retrieval.search_done", "jobId": "j", "ids": ["b"]})
               + "\n" + json.dumps({"event": "retrieval.search_done", "jobId": "k", "tiers": 0, "handed": 0})
               + "\n" + json.dumps({"event": "retrieval.library_search_done", "jobId": "s", "ids": ["c"]}) + "\n")
        self.assertEqual(leak.found_ids(log), {"j": {"a", "b"}, "k": set()})


class ResultTextTest(Recorded):
    def test_results_hold_ids_counts_and_codes_only(self):
        for rec in (self.rec, None):
            result = self.judge(rec) if rec else leak.judge(None, {}, {}, {})
            text = json.dumps(result) + leak.summary(result, {"backend": "b" * 40})
            for secret in SECRETS:
                self.assertNotIn(secret, text)
            for q in QUESTIONS:
                self.assertNotIn(q["question"], text)
            for m in leak.MATERIALS:
                for page in leak.pages(m["source"]):
                    for line in page:
                        if len(line) > 12:
                            self.assertNotIn(line, text)

    def test_summary_names_the_failure(self):
        rec = copy.deepcopy(self.rec)
        ha = self.ids_of("HA")
        self.turn(rec, "livro", "q07")["citations"].append(ha[1])
        text = leak.summary(self.judge(rec), {"backend": "b" * 40})
        self.assertIn("**FAILED**", text)
        self.assertIn(f"- cited · Livro · q07 · HA:{ha[1]}", text)
        self.assertIn("| Casa | R + HA | 40 | 40 |", text)


# ------------------------------------------------------------------ the stage on its own stack

class StageDocker(FakeDocker):
    """Records `run` calls; the runner writes `record` to its /out mount and exits `runner_rc`."""
    def __init__(self, record=None, runner_rc=0, rc=None):
        super().__init__(rc=rc)
        self.record, self.runner_rc = record, runner_rc

    def run(self, name, image, args, **kw):
        self.calls.append((name, image, args, kw))
        if name == "leak-runner":
            out = next(h for h, c, _ in kw["mounts"] if c == "/out")
            self.config = json.loads((next(h for h, c, _ in kw["mounts"] if c == "/in") / "config.json").read_text())
            Path(kw["log"]).write_text("runner: complete")
            if self.record is not None:
                Path(out, "runner.json").write_text(json.dumps(self.record))
            return self.runner_rc
        return self.rc.get(name, 0)


class StageTest(Base):
    @classmethod
    def setUpClass(cls):
        cls.rtmp = Path(tempfile.mkdtemp())
        _, cls.rec, cls.passages, cls.turns, cls.log, _ = record_run(cls.rtmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.rtmp, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.psql_rc = 0
        self.worker_log = self.log
        for name, fn in (("capture", self.leak_capture),
                         ("container_logs", lambda n, dest: Path(dest).write_text(
                             self.worker_log if n.endswith("-leak-worker") else "log"))):
            p = mock.patch.object(leak, name, fn)
            p.start()
            self.addCleanup(p.stop)

    def leak_capture(self, cmd, timeout=120):
        self.cmds.append(cmd)
        if cmd[:2] == ["docker", "exec"] and "psql" in cmd:
            sql = cmd[-1]
            if self.psql_rc:
                return self.psql_rc, ""
            if sql == leak.PASSAGES_SQL:
                return 0, "\n".join(f"{p},{v}" for p, v in self.passages.items())
            return 0, "\n".join(f"{t},{d['job']},{d['campaign']}" for t, d in self.turns.items())
        return self.fake_capture(cmd, timeout)

    def leak_session(self, docker, limit=1800):
        return e2e.Session(s=self.s, id=RUN_ID, docker=docker, dir=self.tmp / "out" / "leak",
                           work=self.tmp / "work" / "leak", rel="leak/", log=lambda m: None,
                           deadline=e2e.time.monotonic() + limit, prefix="leak")

    def run_stage(self, record, runner_rc=0, limit=1800, rc=None):
        docker = StageDocker(record=record, runner_rc=runner_rc, rc=rc)
        sess = self.leak_session(docker, limit)
        self.cmds.clear()
        return leak.execute(sess, self.own("backend")), docker, sess

    def test_pass(self):
        (outcome, m, files, detail), docker, sess = self.run_stage(self.rec)
        self.assertEqual(outcome, "ok", detail)
        self.assertTrue(detail.startswith("80/80 clean, control ok (backend cccccccc, frontend "), detail)
        self.assertEqual((m["verdict"], m["turns"], m["clean"], m["control"]), ("passed", 80, 80, "ok"))
        for f in ("leak/result.json", "leak/summary.md", "leak/runner.json", "leak/runner.log", "leak/leak.log",
                  "leak/backend.log", "leak/frontend.log", "leak/worker.log", "leak/postgres.log",
                  "leak/stand-in-qdrant.log", "leak/stand-in-ollama.log"):
            self.assertIn(f, files)
        saved = json.loads((sess.dir / "result.json").read_text())
        self.assertEqual((saved["verdict"], saved["outcome"], saved["shas"]["backend"]), ("passed", "ok", OWN_SHA))
        self.assertIn("**PASSED**", (sess.dir / "summary.md").read_text())
        names = [c[0] for c in docker.calls]
        self.assertEqual(names, ["leak-postgres", "leak-redis", "leak-stand-in-qdrant", "leak-stand-in-ollama",
                                 "leak-probe", "leak-probe", "probe", "probe", "leak-runner"])
        self.assert_cleaned()

    def test_runner_container(self):
        (_, _, _, _), docker, sess = self.run_stage(self.rec)
        name, image, args, kw = docker.calls[-1]
        self.assertEqual(image, f"gmshield-ci/worker:{self.heads['worker']}")
        self.assertEqual((kw["entrypoint"], args), ("python", ["-I", "/sm1/runner.py", "/in/config.json"]))
        self.assertEqual(kw["network"], f"gmshield-ci-{RUN_ID}-leak")
        self.assertIn((leak.QUALITY, "/sm1", "ro"), kw["mounts"])
        self.assertIn((sess.dir, "/out", "rw"), kw["mounts"])
        self.assertTrue(all(mode == "ro" for _, c, mode in kw["mounts"] if c != "/out"))
        for flag in ("--read-only", "no-new-privileges"):
            self.assertIn(flag, kw["extra"])
        self.assertEqual(kw["extra"][kw["extra"].index("--cap-drop") + 1], "ALL")
        cfg = docker.config
        self.assertEqual((cfg["base"], cfg["code"]), (leak.BACKEND, "stand-in.sm1.leak@example.test"))
        self.assertTrue(leak.BACKEND.endswith("//stand-in-backend:8080"))       # the backend's test-mode name
        self.assertEqual(cfg["credential"], stub.FRONTEND)
        self.assertEqual([m["key"] for m in cfg["materials"]], ["R", "HA", "NB", "X"])
        inputs = sess.work / "in"
        self.assertTrue(all((inputs / m["filename"]).read_bytes().startswith(b"%PDF") for m in cfg["materials"]))
        self.assertLess(cfg["budget"], 1800)

    def assert_cleaned(self):
        removed = [c for c in self.cmds if c[:4] == ["docker", "rm", "-f", "-v"]][-1]
        for n in ("backend", "frontend", "worker", "postgres", "redis", "stand-in-qdrant", "stand-in-ollama"):
            self.assertIn(f"gmshield-ci-{RUN_ID}-leak-{n}", removed)
        self.assertIn(["docker", "network", "rm", f"gmshield-ci-{RUN_ID}-leak"], self.cmds)
        vols = [c for c in self.cmds if c[:4] == ["docker", "volume", "rm", "-f"]][-1]
        self.assertIn(f"gmshield-ci-{RUN_ID}-backend-files", vols)
        create = next(c for c in self.cmds if c[:3] == ["docker", "network", "create"])
        self.assertIn("--internal", create)
        self.assertIn(f"gmshield-ci.run={RUN_ID}", create)
        runs = [c for c in self.cmds if c[:2] == ["docker", "run"]]
        self.assertEqual([r[3] for r in runs], [f"gmshield-ci-{RUN_ID}-leak-{s}" for s in ("backend", "worker",
                                                                                           "frontend")])
        self.assertTrue(all(f"gmshield-ci.run={RUN_ID}" in r for r in runs))

    def test_found_leak_fails_the_stage_and_keeps_the_logs(self):
        ha_version = self.rec["materials"]["HA"]["versionId"]
        ha = sorted(p for p, v in self.passages.items() if v == ha_version)
        job = next(d["job"] for t, d in self.turns.items()
                   if any(x["turnId"] == t and x["campaign"] == "livro" and x["question"] == "q07" and
                          x["phase"] == "main" for x in self.rec["turns"]))
        self.worker_log = self.log + json.dumps({"event": "retrieval.search_done", "jobId": job, "ids": [ha[0]]})
        (outcome, m, files, detail), _, sess = self.run_stage(self.rec)
        self.assertEqual((outcome, m["error"]), ("error", f"leak found: Livro q07 HA:{ha[0]}"))
        saved = json.loads((sess.dir / "result.json").read_text())
        self.assertEqual(saved["verdict"], "failed")
        self.assertIn("leak/worker.log", files)
        self.assertIn("leak/backend.log", files)
        self.assert_cleaned()

    def test_runner_without_record_or_timed_out(self):
        (outcome, m, _, _), _, sess = self.run_stage(None, runner_rc=2)
        self.assertEqual((outcome, m["error"]), ("error", "the runner wrote no record (exit 2)"))
        self.assertEqual(json.loads((sess.dir / "result.json").read_text())["verdict"], "error")
        (outcome, m, _, _), _, _ = self.run_stage(self.rec, runner_rc=124)
        self.assertEqual((outcome, m["error"]), ("error", "timed out"))
        self.assert_cleaned()

    def test_postgres_unreadable(self):
        self.psql_rc = 2
        (outcome, m, _, _), _, _ = self.run_stage(self.rec)
        self.assertEqual((outcome, m["error"]), ("error", "cannot read Postgres (exit 2)"))
        self.assert_cleaned()

    def test_missing_image_unhealthy_app_or_over_limit(self):
        self.images.discard(f"gmshield-ci/worker:{self.heads['worker']}")
        (outcome, m, _, _), docker, _ = self.run_stage(self.rec)
        self.assertEqual((outcome, m["error"]),
                         ("error", "no develop image of GMshield-worker; run its develop pipeline"))
        self.assertEqual(docker.calls, [])
        self.images.add(f"gmshield-ci/worker:{self.heads['worker']}")
        (outcome, m, files, _), docker, _ = self.run_stage(self.rec, rc={"probe": 1})
        self.assertIn("the backend was not healthy at /actuator/health", m["error"])
        self.assertNotIn("leak-runner", [c[0] for c in docker.calls])
        self.assertIn("leak/backend.log", files)
        removed = [c for c in self.cmds if c[:4] == ["docker", "rm", "-f", "-v"]][-1]
        for n in ("backend", "postgres", "redis", "stand-in-qdrant", "stand-in-ollama"):   # all it started
            self.assertIn(f"gmshield-ci-{RUN_ID}-leak-{n}", removed)
        self.assertIn(["docker", "network", "rm", f"gmshield-ci-{RUN_ID}-leak"], self.cmds)
        (outcome, m, _, _), docker, _ = self.run_stage(self.rec, limit=0)
        self.assertEqual((outcome, m["error"]), ("error", "timed out"))
        self.assertNotIn("leak-runner", [c[0] for c in docker.calls])

    def test_results_hold_no_text(self):
        (_, _, _, _), _, sess = self.run_stage(self.rec)
        for name in ("result.json", "summary.md", "runner.json"):
            text = (sess.dir / name).read_text()
            for secret in SECRETS:
                self.assertNotIn(secret, text)
            for q in QUESTIONS:
                self.assertNotIn(q["question"], text)

    def run_like(self, docker=None):
        own = self.own("backend")
        return types.SimpleNamespace(
            contract=own.contract, image_built=True, s=self.s, id=RUN_ID, docker=docker or StageDocker(self.rec),
            dir=self.tmp / "run", work=self.tmp / "run-work", log=lambda m: None,
            repo=types.SimpleNamespace(name="GMshield-backend"), sha=OWN_SHA,
            local_image=f"gmshield-ci/backend:{OWN_SHA}", src=own.src)

    def test_stage_runs_the_run_image_with_the_others_under_its_limit(self):
        seen = {}

        def capture_session(sess, own):
            seen.update(deadline=sess.deadline, prefix=sess.prefix, dir=sess.dir, image=own.image)
            return "ok", {}, [], "d"
        self.s.limits["leak"] = 77
        before = e2e.time.monotonic()
        with mock.patch.object(leak, "execute", capture_session):
            leak.stage(self.run_like())
        self.assertEqual((seen["prefix"], seen["dir"]), ("leak", self.tmp / "run" / "leak"))
        self.assertEqual(seen["image"], f"gmshield-ci/backend:{OWN_SHA}")
        self.assertAlmostEqual(seen["deadline"] - before, 77, delta=2)
        outcome, m, files, detail = leak.stage(self.run_like())
        self.assertEqual(outcome, "ok", detail)
        self.assertIn("leak/result.json", files)

    def test_stage_skips_without_image_and_outside_the_apps(self):
        run = types.SimpleNamespace(contract=types.SimpleNamespace(service="backend"), image_built=False)
        self.assertEqual(leak.stage(run)[0], "skipped")
        run = types.SimpleNamespace(contract=types.SimpleNamespace(service="pipeline"), image_built=True)
        self.assertEqual(leak.stage(run)[0], "skipped")

    def test_e2e_and_leak_never_share_a_name(self):
        e, lk = self.session(), self.leak_session(StageDocker())
        self.assertNotEqual(e2e.network_name(e), e2e.network_name(lk))
        for name in ("backend", "worker", "frontend"):
            self.assertNotEqual(e2e.cname(e, name), e2e.cname(lk, name))
        self.assertNotEqual(e2e.qdrant_args(e)["name"], e2e.qdrant_args(lk)["name"])


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

    def test_only_in_full_develop_runs_of_the_three_apps_after_e2e_without_a_gate(self):
        for svc in ("backend", "frontend", "worker"):
            order = self.flow(svc)
            self.assertEqual([k for k, _, _ in order][-2:], ["e2e", "leak"])
            self.assertEqual(order[-1][1:], (None, leak.stage))
        self.assertEqual(self.flow("worker", mode="light"), [])
        self.assertNotIn("leak", [k for k, _, _ in self.flow("pipeline")])

    def test_not_on_main(self):
        import inspect
        self.assertNotIn("leak", inspect.getsource(pipeline.main_flow))

    def test_a_failed_leak_fails_the_run(self):
        run = types.SimpleNamespace(s=types.SimpleNamespace(gates={}), titles={}, lock=threading.Lock(), records=[],
                                    log=lambda m: None)
        [r] = stages.execute(run, "leak", leak.TITLE, None,
                             lambda run: ("error", {"error": "leak found: Livro q07 HA:x"}, [], "x"))
        self.assertEqual((r.status, r.reasons), ("failed", ["leak found: Livro q07 HA:x"]))
        self.assertFalse(pipeline._passed(run))

    def test_dashboard_column_and_limit(self):
        self.assertIn(("leak", "Leak", "SM-1 leak test"), dashboard.STAGES["develop"])
        tools = config.read_toml(config.RUNNER_DIR / "tools.toml")
        self.assertEqual(tools["limits"]["leak"], leak.DEFAULT_LIMIT)


class StandaloneTest(unittest.TestCase):
    def settings(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        return config.Settings(home=tmp, org="o", branches=("develop",), registry="r", prod_network="p",
                               ci_slice="ci.slice", repos=[], images={}, semgrep_rulesets=[], limits={}, gates={})

    def test_refused_while_a_run_holds_the_poll_lock(self):
        s = self.settings()

        def must_not_run(*a, **k):
            raise AssertionError("the test ran while a pipeline run held the lock")
        with pipeline.single_instance(s) as ok, mock.patch.object(leak, "execute", must_not_run), \
                contextlib.redirect_stdout(io.StringIO()) as said:
            self.assertTrue(ok)
            self.assertEqual(leak.standalone(s), 1)
        self.assertIn("a pipeline run is in progress", said.getvalue())

    def test_folder_name_never_matches_a_run_id(self):
        name = e2e.folder_name(datetime(2026, 11, 22, 1, 2, 3, tzinfo=timezone.utc))
        self.assertEqual(name, "2026-11-22-010203")
        self.assertIsNone(housekeeping.RUN_ID.match(name))

    def test_standalone_cleans_up_and_exits_by_outcome(self):
        s = self.settings()
        cleaned, seen = [], []
        for outcome, rc in (("ok", 0), ("error", 1)):
            def fake(sess, own, outcome=outcome):
                seen.append((sess.prefix, sess.dir.parent, own))
                return outcome, {}, [], "d"
            with mock.patch.object(leak, "execute", fake), \
                    mock.patch.object(leak.Docker, "cleanup", lambda self: cleaned.append(self.label)), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(leak.standalone(s), rc)
        self.assertTrue(all(label.startswith("gmshield-ci.run=leak-") for label in cleaned))
        self.assertEqual(len(cleaned), 2)
        self.assertEqual(seen[0], ("leak", s.artifacts / "quality" / "leak", None))

    def test_the_command(self):
        from gmshield_ci import __main__ as cli
        with mock.patch.object(leak, "standalone", lambda s: 7), mock.patch.object(cli, "load_settings", lambda: None):
            self.assertEqual(cli.main(["leak"]), 7)


if __name__ == "__main__":
    unittest.main()
