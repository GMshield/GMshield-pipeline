"""SM-2 (Story 2.9): the question set's shape, the normaliser, the passage rebuild, and `gmshield_ci sm2` against a
fake backend (tests/fixtures/sm2/stub.py) for each row of the story's matrix. No answer or passage text may reach
the result or standard output. Run: python3 -m unittest tests.test_sm2 -v"""
import contextlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gmshield_ci import housekeeping, sm2

STUB_PATH = Path(__file__).resolve().parent / "fixtures" / "sm2" / "stub.py"
_spec = importlib.util.spec_from_file_location("sm2_stub", STUB_PATH)
stub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stub)

FAST = dict(question_timeout=1.5, read_timeout=0.5, poll_every=0.01, processing_wait=2, review_wait=2,
            first_words_ms=5000, burst_pages=3)
SECRETS = ("ANSWER-SECRET", "PASSAGE-SECRET", "cred-SECRET")


def question(qid: str, scenario: str, pages=(10,), phrases=("fireball deals",), language="en") -> dict:
    return {"id": qid, "language": language, "part": "spells", "exactName": False, "question": scenario,
            "pages": list(pages), "phrases": list(phrases)}


class Run:
    """One `sm2.run` against a stub backend, in a temporary home; keeps exit code, stdout and the result."""

    def __init__(self, test: unittest.TestCase, questions: list[dict], backend: "stub.Backend", **kw):
        self.tmp = Path(test.enterContext(tempfile.TemporaryDirectory()))
        self.qfile = self.tmp / "questions.json"
        self.qfile.write_text(json.dumps(questions))
        self.session = self.tmp / "sm2-session"
        self.session.write_text(backend.token + "\n")
        self.session.chmod(0o600)
        self.artifacts = self.tmp / "artifacts"
        lim = sm2.Limits(**{**FAST, **kw.pop("limits", {})})
        out = io.StringIO()
        target = sm2.Target(backend.base, backend.credential)
        with contextlib.redirect_stdout(out), mock.patch.object(sm2, "releases", return_value={
                s: {"container": f"gmshield-{s}", "sha": "abc1234", "tag": f"r2026.11.20-1200-{s}"}
                for s in sm2.SERVICES}):
            self.code = sm2.run(self.session, target=target, questions_file=self.qfile, lim=lim,
                                artifacts=self.artifacts, **kw)
        self.stdout = out.getvalue()
        folders = list((self.artifacts / "quality" / "sm2").glob("*"))
        self.folder = folders[0] if folders else None
        self.result = json.loads((self.folder / "result.json").read_text()) if self.folder else None
        self.summary = (self.folder / "summary.md").read_text() if self.folder else ""

    def q(self, qid: str) -> dict:
        return next(x for x in self.result["questions"] if x["id"] == qid)

    def assert_no_text(self, test: unittest.TestCase) -> None:
        raw = json.dumps(self.result) + self.summary + self.stdout
        for secret in SECRETS:
            test.assertNotIn(secret, raw)


class NormaliseTest(unittest.TestCase):
    def test_hyphen_at_a_line_end_is_joined(self):
        self.assertEqual(sm2.normalise("A trap in-\ncludes any object"), "a trap includes any object")
        self.assertTrue(sm2.holds_phrase("A trap, for this spell, in-  \n  cludes any object", ["spell, includes any"]))

    def test_a_real_hyphen_at_a_line_end_is_kept_too(self):
        self.assertTrue(sm2.holds_phrase("a two-\nhanded sword", ["two-handed sword"]))
        self.assertTrue(sm2.holds_phrase("a two-\nhanded sword", ["twohanded"]))

    def test_ligatures_case_and_spaces(self):
        self.assertTrue(sm2.holds_phrase("The ﬁery  EXPLOSION\n blossoms", ["fiery explosion blossoms"]))
        self.assertTrue(sm2.holds_phrase("Straße", ["STRASSE"]))           # casefold, not lower
        self.assertTrue(sm2.holds_phrase("you don’t provoke", ["don't provoke"]))

    def test_no_phrase_no_match(self):
        self.assertFalse(sm2.holds_phrase("nothing here", ["fireball deals"]))
        self.assertFalse(sm2.holds_phrase("anything", ["", "   "]))


class RebuildTest(unittest.TestCase):
    def test_from_boxes_takes_only_the_overlapping_lines(self):
        text = sm2.passage_text(stub.VIEWS[10], "P1")
        self.assertIn("ball deals", text)
        self.assertNotIn("Heading", text)
        self.assertNotIn("below the passage", text)       # touches the passage's edge only
        self.assertNotIn("Other column", text)
        self.assertTrue(sm2.holds_phrase(text, ["fireball deals"]))

    def test_from_a_range_in_code_points(self):
        self.assertTrue(sm2.passage_text(stub.VIEWS[20], "P4").startswith("The range holds"))

    def test_a_passage_not_on_the_page(self):
        self.assertIsNone(sm2.passage_text(stub.VIEWS[10], "P4"))


class QuestionSetTest(unittest.TestCase):
    def setUp(self):
        self.qs = json.loads(sm2.QUESTIONS.read_text(encoding="utf-8"))

    def test_the_fixed_set_is_valid(self):
        self.assertEqual(sm2.check_questions(self.qs), [])
        self.assertEqual(len(self.qs), 50)
        langs = [q["language"] for q in self.qs]
        self.assertEqual((langs.count("en"), langs.count("pt-BR")), (25, 25))

    def test_phrases_are_short_and_ids_unique(self):
        self.assertEqual(len({q["id"] for q in self.qs}), 50)
        for q in self.qs:
            for ph in q["phrases"]:
                self.assertLessEqual(len(ph.split()), sm2.MAX_PHRASE_WORDS, q["id"])

    def test_spread_over_the_srd_parts_with_exact_names(self):
        parts = {q["part"] for q in self.qs}
        self.assertEqual(parts, {"rules", "glossary", "classes", "spells", "magic_items", "monsters"})
        self.assertGreaterEqual(sum(q["exactName"] for q in self.qs), 3)

    def test_attribution_is_beside_it(self):
        text = (sm2.QUESTIONS.parent / "ATTRIBUTION.txt").read_text(encoding="utf-8")
        self.assertIn("Creative Commons Attribution 4.0", text)
        self.assertIn("SRD 5.2.1", text)

    def test_problems_are_named(self):
        bad = self.qs[:49] + [{**self.qs[0], "phrases": ["one two three four five six seven eight nine ten eleven "
                                                         "twelve thirteen fourteen fifteen sixteen"]}]
        problems = sm2.check_questions(bad)
        self.assertTrue(any("duplicate id" in p for p in problems))
        self.assertTrue(any("1 to 15 words" in p for p in problems))
        self.assertTrue(any("25 in Portuguese" in p for p in problems))


class RunTest(unittest.TestCase):
    def test_pass_and_failures_by_reason(self):
        qs = [question("q-boxes", "pass-boxes"),
              question("q-range", "pass-range", pages=(20,), phrases=("range holds the answer",)),
              question("q-span", "pass-span", pages=(30, 31), phrases=("answer continues here",)),
              question("q-missing", "phrase-missing"),
              question("q-wrong", "wrong-page"),
              question("q-silent", "silent"),
              question("q-error", "error"),
              question("q-timeout", "timeout"),
              question("q-stopped", "stopped")]
        with stub.Backend() as b:
            r = Run(self, qs, b, skip_burst=True)
        self.assertEqual(r.code, sm2.EXIT_FAIL)
        self.assertEqual([r.q(i)["verdict"] for i in ("q-boxes", "q-range", "q-span")], ["pass"] * 3)
        self.assertEqual(r.q("q-boxes")["citedPages"], [10])
        self.assertEqual(r.q("q-range")["citedPages"], [20, 99])
        self.assertEqual(r.q("q-span")["references"][0]["nextView"], 200)
        self.assertEqual((r.q("q-missing")["verdict"], r.q("q-missing")["reason"]), ("fail", "phrase_missing"))
        self.assertEqual(r.q("q-wrong")["reason"], "wrong_page")
        self.assertEqual(r.q("q-silent")["reason"], "silent")
        self.assertEqual(r.q("q-error")["reason"], "model.unavailable")
        self.assertEqual(r.q("q-timeout")["reason"], "timeout")
        self.assertIn(r.q("q-timeout")["turnId"], b.stopped)
        self.assertEqual(r.q("q-stopped")["reason"], "stopped")
        self.assertEqual(r.result["failuresByReason"], {"model.unavailable": 1, "phrase_missing": 1, "silent": 1,
                                                       "stopped": 1, "timeout": 1, "wrong_page": 1})
        self.assertEqual(r.result["gates"]["sourced"], {"passed": 3, "of": 9, "need": 9, "ok": False})
        self.assertEqual(r.result["gates"]["burst"]["status"], "skipped")
        self.assertEqual(r.result["status"], "fail")
        self.assertIn("phrase_missing: 1", r.summary)
        r.assert_no_text(self)

    def test_all_gates_pass_with_the_burst(self):
        qs = [question(f"q{i}", "burst") for i in range(5)]
        with stub.Backend() as b:
            r = Run(self, qs, b)
        self.assertEqual(r.code, sm2.EXIT_PASS, r.stdout)
        self.assertEqual(r.result["status"], "pass")
        burst = r.result["burst"]
        self.assertEqual((burst["status"], burst["stateBefore"], burst["stateAfterAsk"]),
                         ("pass", "processing", "processing"))
        self.assertEqual(len(burst["questions"]), 5)
        self.assertTrue(all(q["done"] for q in burst["questions"]))
        self.assertEqual(b.max_open_turns, 5)                          # the five were in progress at once
        self.assertEqual((burst["finalState"], burst["discard"]), ("needs_review", "discarded"))
        self.assertEqual(b.discarded, [stub.MATERIAL])
        self.assertTrue(b.upload.startswith(b"%PDF-1.4"))
        self.assertEqual(b.upload.count(b"/Type /Page "), 3)
        self.assertTrue(all(g["ok"] for g in r.result["gates"].values()))
        r.assert_no_text(self)

    def test_a_burst_question_ending_in_error_fails_the_burst(self):
        qs = [question(f"q{i}", "burst") for i in range(4)] + [question("q4", "error")]
        with stub.Backend() as b:
            r = Run(self, qs, b)
        self.assertEqual(r.code, sm2.EXIT_FAIL)
        self.assertEqual(r.result["burst"]["status"], "fail")
        self.assertEqual(r.result["gates"]["burst"]["done"], 4)
        self.assertIs(r.result["gates"]["burst"]["ok"], False)
        self.assertEqual(b.discarded, [stub.MATERIAL])

    def test_burst_material_still_processing_cannot_be_discarded_and_says_so(self):
        with stub.Backend(material_states=["waiting", "processing"]) as b:
            r = Run(self, [question(f"q{i}", "burst") for i in range(5)], b)
        burst = r.result["burst"]
        self.assertEqual((burst["finalState"], burst["discard"]), ("processing", "not possible"))
        self.assertFalse(any(p.endswith("/discard") for _, p in b.calls))
        self.assertIn(f"WARNING burst material {stub.MATERIAL}", r.stdout)

    def test_burst_material_finished_early_is_invalid_and_still_discarded(self):
        with stub.Backend(material_states=["needs_review"]) as b:
            r = Run(self, [question(f"q{i}", "pass-boxes") for i in range(5)], b)
        self.assertEqual(r.code, sm2.EXIT_FAIL)
        self.assertEqual(r.result["burst"]["status"], "invalid")
        self.assertEqual(r.result["gates"]["burst"], {"status": "invalid", "done": 0, "of": 5, "ok": False})
        self.assertEqual(b.discarded, [stub.MATERIAL])

    def test_slow_first_words_fail_their_gate(self):
        with stub.Backend() as b:
            r = Run(self, [question("q1", "slow"), question("q2", "pass-boxes")], b, skip_burst=True,
                    limits={"first_words_ms": 300})
        self.assertGreater(r.q("q1")["firstWordsMs"], 300)
        self.assertEqual(r.result["gates"]["firstWords"]["within"], 1)
        self.assertFalse(r.result["gates"]["firstWords"]["ok"])
        self.assertEqual(r.q("q1")["verdict"], "pass")

    def test_a_reference_that_does_not_open_fails_its_gate_but_the_run_continues(self):
        with stub.Backend() as b:
            r = Run(self, [question("q1", "no-picture"), question("q2", "pass-boxes")], b, skip_burst=True)
        unopened = r.result["gates"]["referencesOpen"]["unopened"]
        self.assertEqual([(u["question"], u["view"], u["picture"]) for u in unopened], [("q1", 200, 404)])
        self.assertEqual(len(r.result["questions"]), 2)
        self.assertIn("References that did not open", r.summary)

    def test_a_cut_stream_is_reopened_after_the_last_event(self):
        with stub.Backend() as b:
            r = Run(self, [question("q1", "cut")], b, skip_burst=True)
        self.assertEqual(r.q("q1")["verdict"], "pass")
        self.assertEqual(r.q("q1")["deltas"], 1)
        self.assertEqual(sum(1 for m, p in b.calls if p.endswith("/events")), 2)

    def test_a_stream_cut_mid_chunk_is_reopened(self):
        with stub.Backend() as b:
            r = Run(self, [question("q1", "chunk-cut"), question("q2", "pass-boxes")], b, skip_burst=True)
        self.assertEqual([q["verdict"] for q in r.result["questions"]], ["pass", "pass"])
        self.assertEqual(r.q("q1")["deltas"], 1)
        self.assertEqual(sum(1 for m, p in b.calls if p == "/api/v1/turns/turn-1/events"), 2)

    def test_renewal_required_stops_with_a_partial_result(self):
        with stub.Backend(renewal_required_after_turns=2) as b:
            r = Run(self, [question(f"q{i}", "pass-boxes") for i in range(4)], b, skip_burst=True)
        self.assertEqual(r.code, sm2.EXIT_STOPPED)
        self.assertEqual(r.result["status"], "incomplete")
        self.assertEqual(len(r.result["questions"]), 2)
        self.assertIn("session.renewal_required", r.result["stoppedBy"])

    def test_a_lost_renewal_reply_is_not_retried(self):
        with stub.Backend() as b:
            api = sm2.Api(sm2.Target(b.base, b.credential), mock.Mock(token="tok-0"))
            with mock.patch.object(api, "call", return_value=sm2.Reply(503, {}, b"")) as call:
                with self.assertRaisesRegex(sm2.SessionStopped, "may have rotated"):
                    api.renew_if_due(force=True)
        self.assertEqual(call.call_count, 1)

    def test_an_interrupt_still_writes_the_partial_result(self):
        with stub.Backend() as b, mock.patch.object(sm2, "run_question", side_effect=KeyboardInterrupt):
            r = Run(self, [question("q1", "pass-boxes")], b, skip_burst=True)
        self.assertEqual(r.code, sm2.EXIT_STOPPED)
        self.assertEqual(r.result["stoppedBy"], "interrupted")

    def test_session_renewed_before_each_question_and_written_back(self):
        with stub.Backend(renew_after=0) as b:
            r = Run(self, [question("q1", "pass-boxes"), question("q2", "pass-boxes")], b, skip_burst=True)
            self.assertEqual(r.session.read_text().strip(), b.token)
        self.assertEqual(b.renewals, 3)                    # at the start, then before each question
        self.assertEqual(stat.S_IMODE(r.session.stat().st_mode), 0o600)
        self.assertEqual(r.result["sessionRenewals"], 3)
        self.assertNotIn(b.token, r.stdout + json.dumps(r.result))

    def test_renewal_refused_stops_with_a_partial_result(self):
        with stub.Backend(renew_after=0, renewals_allowed=2) as b:
            r = Run(self, [question(f"q{i}", "pass-boxes") for i in range(4)], b)
        self.assertEqual(r.code, sm2.EXIT_STOPPED)
        self.assertEqual(r.result["status"], "incomplete")
        self.assertEqual(len(r.result["questions"]), 1)
        self.assertIn("session.required", r.result["stoppedBy"])
        self.assertIsNone(r.result["burst"])

    def test_refuses_to_start_while_indexing(self):
        with stub.Backend(indexing={"remaining": 12}) as b:
            r = Run(self, [question("q1", "pass-boxes")], b)
        self.assertEqual(r.code, sm2.EXIT_STOPPED)
        self.assertIsNone(r.result)
        self.assertIn("indexing is still running", r.stdout)
        self.assertFalse(any("/turns" in p for _, p in b.calls))

    def test_refuses_to_start_without_an_accepted_source(self):
        with stub.Backend(has_sources=False) as b:
            r = Run(self, [question("q1", "pass-boxes")], b)
        self.assertEqual(r.code, sm2.EXIT_STOPPED)
        self.assertIsNone(r.result)
        self.assertIn("no accepted source", r.stdout)
        self.assertFalse(any("/turns" in p for _, p in b.calls))

    def test_a_token_renewed_elsewhere_is_named(self):
        with stub.Backend() as b:
            b.previous.add("tok-old")
            b.token = "tok-new"
            tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
            (tmp / "q.json").write_text(json.dumps([question("q1", "pass-boxes")]))
            (tmp / "s").write_text("tok-old.1763640000\n")         # a whole cookie value is accepted
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = sm2.run(tmp / "s", target=sm2.Target(b.base, b.credential), questions_file=tmp / "q.json",
                               lim=sm2.Limits(**FAST), artifacts=tmp / "a")
        self.assertEqual(code, sm2.EXIT_STOPPED)
        self.assertIn("session.already_renewed", out.getvalue())
        self.assertIn("renewed elsewhere", out.getvalue())

    def test_result_folder_is_dated_named_by_release_and_left_alone_by_housekeeping(self):
        with stub.Backend() as b:
            r = Run(self, [question("q1", "pass-boxes")], b, skip_burst=True)
        self.assertRegex(r.folder.name, r"^\d{4}-\d{2}-\d{2}-\d{6}-r2026\.11\.20-1200-backend$")
        self.assertIsNone(housekeeping.RUN_ID.match(r.folder.name))
        self.assertEqual(r.result["release"]["worker"]["tag"], "r2026.11.20-1200-worker")
        self.assertFalse(list(r.artifacts.rglob("history.jsonl")))


class CliTest(unittest.TestCase):
    def test_sm2_subcommand_passes_its_options(self):
        from gmshield_ci import __main__ as cli
        with mock.patch.object(sm2, "run", return_value=1) as run:
            code = cli.main(["sm2", "--skip-burst", "--backend-container", "gm27-backend", "--network", "gm27-app",
                             "--session-file", "/x/session", "--questions", "/y/q.json"])
        self.assertEqual(code, 1)
        run.assert_called_once_with(Path("/x/session"), backend_container="gm27-backend", network="gm27-app",
                                    questions_file=Path("/y/q.json"), skip_burst=True)


class TargetTest(unittest.TestCase):
    """Target and release resolution with `docker` replaced by the stub."""

    def setUp(self):
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bin = tmp / "bin"
        self.bin.mkdir()
        (self.bin / "docker").symlink_to(STUB_PATH)
        STUB_PATH.chmod(STUB_PATH.stat().st_mode | 0o111)
        self.state = tmp / "docker.json"
        self.artifacts = tmp / "artifacts"
        self.enterContext(mock.patch.dict(os.environ, {"PATH": f"{self.bin}:{os.environ['PATH']}",
                                                       "SM2_DOCKER_STATE": str(self.state)}))

    def docker(self, **containers):
        self.state.write_text(json.dumps(containers))

    def test_address_and_credential_from_the_container(self):
        self.docker(**{"gm27-backend": {"networks": {"gm27-app": "172.30.9.4", "gm27-data": "172.30.8.4"},
                                        "env": ["GMSHIELD_X=1", "GMSHIELD_FRONTEND_CREDENTIAL=cred=with=equals"]}})
        t = sm2.resolve_target("gm27-backend", "gm27-app")
        self.assertEqual(t.base, "http://172.30.9.4:8080")
        self.assertEqual(t.credential, "cred=with=equals")
        self.assertNotIn("cred", repr(t))

    def test_refusals_name_what_is_missing(self):
        self.docker(**{"gmshield-backend": {"networks": {"other": "10.0.0.2"}, "env": []}})
        with self.assertRaisesRegex(sm2.Refused, "no address on network gmshield-app"):
            sm2.resolve_target("gmshield-backend", "gmshield-app")
        with self.assertRaisesRegex(sm2.Refused, "not found"):
            sm2.resolve_target("nothing", "gmshield-app")
        self.docker(**{"gmshield-backend": {"networks": {"gmshield-app": "10.0.0.2"}, "env": []}})
        with self.assertRaisesRegex(sm2.Refused, "GMSHIELD_FRONTEND_CREDENTIAL"):
            sm2.resolve_target("gmshield-backend", "gmshield-app")

    def test_release_tags_from_labels_images_and_release_files(self):
        full = "abcdef1234567890abcdef1234567890abcdef12"
        for repo, tag, at in (("GMshield-backend", "r2026.11.18-1000-abcdef12", "2026-11-18T10:00:00"),
                              ("GMshield-backend", "r2026.11.20-0900-abcdef12", "2026-11-20T09:00:00")):
            d = self.artifacts / repo / "releases" / tag
            d.mkdir(parents=True)
            (d / "release.json").write_text(json.dumps({"tag": tag, "sha": full, "at": at}))
        self.docker(**{"gmshield-backend": {"labels": {"gmshield.sha": full}},
                       "gmshield-frontend": {"labels": {"gmshield.sha": "1234567890ab"}},
                       "gm27-backend": {"labels": None, "image": f"gmshield-ci/backend:{full[:12]}"}})
        rel = sm2.releases(self.artifacts, "gmshield-backend")
        self.assertEqual(rel["backend"]["tag"], "r2026.11.20-0900-abcdef12")       # the newest release of it
        self.assertEqual(rel["frontend"]["tag"], "1234567890ab")                  # no release: the sha
        self.assertEqual(rel["worker"]["tag"], "unknown")                         # no container
        temp = sm2.releases(self.artifacts, "gm27-backend")
        self.assertEqual(temp["backend"]["tag"], "r2026.11.20-0900-abcdef12")     # from the image tag
        self.assertEqual(temp["frontend"]["container"], "gm27-frontend")


class PdfTest(unittest.TestCase):
    def test_generated_pdf_has_its_pages_and_a_valid_xref(self):
        pdf = sm2.generated_pdf(60, "20261120120000")
        self.assertEqual(pdf.count(b"/Type /Page "), 60)
        self.assertIn(b"/Count 60", pdf)
        xref = int(pdf.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
        self.assertTrue(pdf[xref:].startswith(b"xref\n"))
        offsets = [int(line[:10]) for line in pdf[xref:].split(b"\n")[3:] if line.endswith(b" n ")]
        for i, off in enumerate(offsets, 1):
            self.assertTrue(pdf[off:].startswith(b"%d 0 obj" % i))
        self.assertNotEqual(pdf, sm2.generated_pdf(60, "20261120120001"))


if __name__ == "__main__":
    unittest.main()
