"""SM-1 with the real model (Story 3.13, part B): `gmshield_ci sm1` against a stub backend (tests/fixtures/sm1/stub.py,
with fake `docker logs` and `inspect`) for each row of the story's matrix; the job-to-turn mapping from the backend's
log; the markers file and its normalisation; the deletion phase; that a missing or stale session or a held poll lock
makes nothing. No answer, passage or name text may reach the result or standard output.
Run: python3 -m unittest tests.test_sm1 -v"""
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import signal
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gmshield_ci import config, leak, pipeline, sm1, sm2

STUB_PATH = Path(__file__).resolve().parent / "fixtures" / "sm1" / "stub.py"
_spec = importlib.util.spec_from_file_location("sm1_stub_b", STUB_PATH)
stub = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stub)

runner = sm1.load_runner()
QUESTIONS = leak.questions()
TEXT = {q["id"]: q["question"] for q in QUESTIONS}
GIVEN = "tok-given-SECRET"
PREVIOUS = "0190a0b0-0000-7000-8000-00000000c0de"
SECRETS = ("ANSWER-SECRET", "PASSAGE-SECRET", "NAME-SECRET", GIVEN, stub.FRONTEND)
FAST = dict(question=10, material=10, indexing=10, poll=0.001, budget=600, deletion=1, deleted_wait=0.05,
            log_every=0.001)


def settings(test: unittest.TestCase) -> config.Settings:
    tmp = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
    return config.Settings(home=tmp, org="o", branches=("develop",), registry="r", prod_network="p",
                           ci_slice="ci.slice", repos=[], images={}, semgrep_rulesets=[], limits={}, gates={})


class Run:
    """One `sm1.run` against the stub; keeps the exit code, stdout, the result, the summary and the stub's state."""

    def __init__(self, test: unittest.TestCase, keep: bool = False, session: str | None = GIVEN, lock_held=False,
                 logs_readable=("backend", "worker"), limits: dict | None = None, truncated=(), **behaviour):
        self.s = settings(test)
        self.session = self.s.home / "sm1-session"
        if session is not None:
            self.session.write_text(session + "\n")
            self.session.chmod(0o600)
        behaviour.setdefault("given", GIVEN)
        behaviour.setdefault("current", PREVIOUS)
        out = io.StringIO()
        self.since: list[tuple[str, str]] = []
        with stub.Backend(**behaviour) as backend:
            self.backend = backend
            target = sm2.Target(backend.base, stub.FRONTEND, "gmshield-backend", "gmshield-app")

            def logs(container: str, since: str):
                test.assertRegex(since, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
                which = {"gmshield-backend": "backend", "gmshield-worker": "worker"}[container]
                self.since.append((which, since))
                if which not in logs_readable:
                    return None
                text = backend.backend_log() if which == "backend" else backend.worker_log()
                if which in truncated:                    # the oldest line read is later than the run's start
                    text = "".join("2099-01-01T00:00:00.000000000Z" + line[30:] + "\n" for line in text.splitlines())
                return text

            with contextlib.ExitStack() as stack:
                stack.enter_context(contextlib.redirect_stdout(out))
                stack.enter_context(mock.patch.object(sm1, "container_log", logs))
                stack.enter_context(mock.patch.object(sm2, "releases", return_value={
                    s: {"container": f"gmshield-{s}", "sha": "abc1234", "tag": f"r2026.11.23-0100-{s}"}
                    for s in sm2.SERVICES}))
                if lock_held:
                    held = stack.enter_context(pipeline.single_instance(self.s))
                    test.assertTrue(held)
                self.code = sm1.run(self.session, settings=self.s, target=target, keep=keep,
                                    lim=sm1.Limits(**{**FAST, **(limits or {})}))
        self.state = backend.state
        self.stdout = out.getvalue()
        folders = sorted((self.s.artifacts / "quality" / "sm1").glob("*"))
        self.folder = folders[0] if folders else None
        self.res = json.loads((self.folder / "result.json").read_text()) if self.folder else None
        self.summary = (self.folder / "summary.md").read_text() if self.folder else ""

    def assert_no_text(self, test: unittest.TestCase, *more: str) -> None:
        raw = json.dumps(self.res) + self.summary + self.stdout
        for secret in SECRETS + more:
            test.assertNotIn(secret, raw)


# ------------------------------------------------------------------ the markers

class MarkersTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(sm1.MARKERS.read_text(encoding="utf-8"))
        self.texts = {m["key"]: runner.normalise((leak.LIBRARY / m["source"]).read_text(encoding="utf-8"))
                      for m in leak.MATERIALS}

    def test_normalisation_folds_case_accents_and_whitespace(self):
        self.assertEqual(runner.normalise("  Ninguém\n ROLA\tIniciativa "), "ninguem rola iniciativa")
        self.assertEqual(runner.markers_in("ninguem  rola\n INICIATIVA aqui", {"HA": ["Ninguém rola iniciativa"]}),
                         ["HA:Ninguém rola iniciativa"])
        self.assertEqual(runner.markers_in("O CONVES do navio", {"X": ["convés"]}), ["X:convés"])
        self.assertEqual(runner.markers_in("dano “triplicado”", {"HA": ["triplicado"]}), ["HA:triplicado"])

    def test_a_term_matches_at_the_start_of_a_word_only(self):
        self.assertEqual(runner.markers_in("dois tripulantes", {"X": ["tripulante"]}), ["X:tripulante"])
        self.assertEqual(runner.markers_in("rolou 14d6", {"HA": ["4d6"]}), [])
        self.assertEqual(runner.markers_in("rolou 4d6.", {"HA": ["4d6"]}), ["HA:4d6"])
        self.assertEqual(runner.markers_in("nada aqui", {"HA": ["corvoalto"]}), [])

    def test_a_stem_covers_the_inflections_and_the_longer_term_is_named(self):
        terms = sm1.load_markers()["terms"]
        for word in ("triplica", "triplicada", "triplo", "tripled", "triple damage"):
            self.assertEqual([m for m in runner.markers_in(word, terms) if m.startswith("HA:tripl")], ["HA:tripl"],
                             word)
        self.assertEqual(runner.markers_in("o dano é triplicado", terms), ["HA:triplicado"])
        self.assertIn("HA:five fail", runner.markers_in("five failures", terms))

    def test_each_material_term_is_its_own_and_no_question_holds_one(self):
        uses = {"HA": ("R", "NB"), "NB": ("R", "HA"), "X": ("R", "HA", "NB")}   # what a forbidding campaign may use
        questions = [runner.normalise(q["question"]) for q in QUESTIONS]
        for key, m in self.data["materials"].items():
            for term in m["markers"] + m["phrases"]:
                self.assertTrue(runner.markers_in(self.texts[key], {key: [term]}), f"{key}: {term} not in its text")
            for term in m["markers"] + m["phrases"] + m["translations"]:
                for other in uses[key]:
                    self.assertFalse(runner.markers_in(self.texts[other], {key: [term]}), f"{key}: {term} in {other}")
                for q in questions:
                    self.assertFalse(runner.markers_in(q, {key: [term]}), f"{key}: {term} in a question")

    def test_house_markers_and_forbidden_materials(self):
        self.assertTrue({q["marker"] for q in QUESTIONS if q["kind"] == "house"} <= set(
            self.data["materials"]["HA"]["markers"]))
        self.assertIn("triplicado", self.data["materials"]["HA"]["phrases"])
        self.assertEqual(self.data["forbidden"], {"casa": ["NB", "X"], "livro": ["HA", "X"]})
        m = sm1.load_markers()
        self.assertEqual(set(m["terms"]), {"HA", "NB", "X"})


# ------------------------------------------------------------------ the matrix, end to end against the stub

class MatrixTest(unittest.TestCase):
    def test_clean_run(self):
        r = Run(self)
        self.assertEqual(r.code, 0, r.stdout)
        self.assertEqual(r.res["status"], "pass")
        self.assertEqual(r.res["reason"], "80/80 clean, 0 restated (Casa 40/40, Livro 40/40)")
        self.assertRegex(r.folder.name, r"^\d{4}-\d\d-\d\d-\d{6}-r2026\.11\.23-0100-backend$")
        self.assertTrue(all(c["ok"] for c in r.res["result"]["checks"].values()), r.res["result"]["checks"])
        n = r.res["result"]["checks"]["notEmpty"]
        self.assertEqual((n["casaHouseCiteHA"], n["casaHouseOf"], n["livroNotesCiteNB"], n["livroNotesOf"]),
                         (24, 24, 8, 8))
        self.assertEqual({k: m["passages"] for k, m in r.res["result"]["materials"].items()},
                         {"R": 2, "HA": 2, "NB": 2, "X": 2})
        self.assertIn("80/80 clean, 0 restated", r.stdout)
        self.assertIn("Livro: no answer mentioned the house rule", r.stdout)
        self.assertIn("| 5. Livro never mentions the house rule | PASS |", r.summary)
        self.assertIn("Livro (by the book): no answer mentioned the house rule.", r.summary)
        self.assertEqual(r.res["release"]["worker"]["tag"], "r2026.11.23-0100-worker")
        self.assertIn("Casa house answers citing HA 24/24 (need 20), Livro notes answers citing NB 8/8 (need 6)",
                      r.summary)
        r.assert_no_text(self)

    def test_names_carry_the_run_suffix_and_scopes_stay_at_their_defaults(self):
        r = Run(self)
        suffix = r.res["suffix"]
        self.assertRegex(suffix, r"^sm1 \d{4}-\d\d-\d\d \d{6}$")
        self.assertEqual(sorted(r.state.systems.values()), [f"Mar de Cinzas · {suffix}", f"Vale de Ferro · {suffix}"])
        self.assertEqual(sorted(c["name"] for c in r.state.campaigns.values()),
                         [f"Casa · {suffix}", f"Livro · {suffix}"])
        self.assertTrue(all(c["scope"]["otherTier"] is False and c["scope"]["version"] == 0
                            for c in r.state.campaigns.values()))

    def test_the_session_is_renewed_and_written_back_and_the_current_campaign_put_back(self):
        r = Run(self)
        token = r.session.read_text().strip()
        self.assertNotEqual(token, GIVEN)
        self.assertIn(token, r.state.tokens)
        self.assertNotIn(GIVEN, r.state.tokens)
        self.assertEqual(stat.S_IMODE(r.session.stat().st_mode), 0o600)
        self.assertGreaterEqual(r.res["sessionRenewals"], 1)
        self.assertEqual(r.state.current, PREVIOUS)
        self.assertTrue(r.res["currentRestored"])

    def test_the_library_is_deleted_at_the_end(self):
        r = Run(self)
        self.assertEqual(r.state.deleting, set(r.state.systems))
        d = r.res["deletion"]
        self.assertTrue(d["finished"])
        self.assertFalse(d["kept"])
        self.assertEqual([(s["key"], s["delete"], s["gone"], s["deleted"]) for s in d["systems"]],
                         [("vale", "started", True, True), ("mar", "started", True, True)])
        self.assertIn("- Finished: system", r.summary)
        self.assertIn("library deleted", r.stdout)
        backend_since = [since for which, since in r.since if which == "backend"]
        self.assertEqual(len(set(backend_since)), 2)              # the polls from the deletion's start, one full read
        self.assertLess(backend_since[-1], backend_since[0])
        self.assertNotIn("may remain", r.summary)
        self.assertFalse(r.res["logs"]["backend"]["possiblyTruncated"])

    def test_keep_skips_the_deletion_and_says_what_was_kept(self):
        r = Run(self, keep=True)
        self.assertEqual(r.code, 0)
        self.assertEqual(r.state.deleting, set())
        self.assertTrue(r.res["deletion"]["kept"])
        self.assertFalse(r.res["deletion"]["finished"])
        self.assertIn("Kept (`--keep`)", r.summary)
        for sid, name in r.state.systems.items():
            self.assertIn(f"system `{sid}` \"{name}\"", r.summary)
        self.assertIn("library kept (--keep)", r.stdout)

    def test_a_deletion_the_backend_never_logs_is_recorded_as_not_finished(self):
        r = Run(self, deleted_log=False)
        self.assertEqual(r.code, 0)
        self.assertFalse(r.res["deletion"]["finished"])
        self.assertIn("NOT finished", r.summary)
        self.assertIn("deletion not logged", r.summary)
        self.assertIn("The library may remain in the account", r.summary)

    def test_livro_restates_the_house_rule(self):
        r = Run(self, say={"Livro": {TEXT["q07"]: ["ANSWER-SECRET o dano é TRIP", "LICADO"]},
                           "Casa": {TEXT["q07"]: ["ANSWER-SECRET regra corvoalto"]}})
        self.assertEqual(r.code, 1)
        self.assertEqual(r.res["reason"], "restated: Livro q07 HA:triplicado")
        self.assertIn("restated: Livro q07 HA:triplicado", r.stdout)
        self.assertIn("sm1: Livro: q07 HA:triplicado", r.stdout)
        self.assertIn("| 5. Livro never mentions the house rule | FAIL | q07 HA:triplicado |", r.summary)
        self.assertIn("the house rule was mentioned in q07 (HA:triplicado).", r.summary)
        casa = next(t for t in r.res["result"]["turnsDetail"] if (t["campaign"], t["question"]) == ("Casa", "q07"))
        self.assertEqual((casa["markers"], casa["clean"]), (["HA:corvoalto"], True))     # Casa may say it
        self.assertEqual(r.state.deleting, set(r.state.systems))                       # deleted after a failure too
        r.assert_no_text(self, "TRIP", "LICADO", "o dano")

    def test_an_accented_spaced_phrase_and_another_systems_marker_are_restatements(self):
        r = Run(self, say={"Livro": {TEXT["q21"]: ["ANSWER-SECRET ninguem  ROLA\n iniciativa"]},
                           "Casa": {TEXT["q13"]: ["ANSWER-SECRET a ferreira ODILIA e um tripulante"]}})
        self.assertEqual(r.code, 1)
        fails = r.res["result"]["checks"]["restated"]["failures"]
        self.assertEqual([(f["campaign"], f["question"], f["markers"]) for f in fails],
                         [("Casa", "q13", ["NB:Odília", "X:tripulante"]),
                          ("Livro", "q21", ["HA:Ninguém rola iniciativa"])])
        self.assertEqual([f["question"] for f in r.res["result"]["checks"]["houseRuleInLivro"]["failures"]], ["q21"])

    def test_out_of_scope_id_found_and_cited(self):
        r = Run(self, leak="casa")
        self.assertEqual(r.code, 1)
        ha = sorted(p for p, k in self._material_of(r).items() if k == "HA")
        self.assertEqual(r.res["reason"], f"leak found: Livro q01 HA:{ha[0]}, HA:{ha[1]}")
        cited = r.res["result"]["checks"]["cited"]["failures"]
        self.assertEqual(len(cited), 40)
        self.assertEqual(r.state.deleting, set(r.state.systems))

    def test_records_cited_within_the_scope_pass_and_a_leaked_record_is_named(self):
        # Story 4.3 part C: each material's record ids are read from its systems' record lists, so a record the answer
        # finds and cites stands for its material; a record of another campaign's material is a leak.
        r = Run(self, records=True)
        self.assertEqual(r.code, 0, r.res["reason"])
        materials = r.res["result"]["materials"]
        self.assertEqual({k: m["records"] for k, m in materials.items()}, {"R": 1, "HA": 1, "NB": 1, "X": 1})
        self.assertIn("Records (record lists): R 1, HA 1, NB 1, X 1", r.summary)
        r.assert_no_text(self)
        r = Run(self, records=True, leak="casa", found_only=True)
        self.assertEqual(r.code, 1)
        version = r.res["result"]["materials"]["HA"]["versionId"]
        ha = next(rid for rid, v in r.state.record_rows.items() if v == version)
        found = r.res["result"]["checks"]["found"]["failures"]
        self.assertEqual(len(found), 40)
        self.assertTrue(all({"id": ha, "material": "HA"} in f["foreign"] for f in found))

    def test_out_of_scope_id_found_only_or_cited_only(self):
        r = Run(self, leak="casa", found_only=True)
        self.assertTrue(r.res["reason"].startswith("leak found: Livro q01 HA:"), r.res["reason"])
        self.assertTrue(r.res["result"]["checks"]["cited"]["ok"])
        r = Run(self, cite_only="casa")
        self.assertEqual(r.code, 1)
        self.assertTrue(r.res["reason"].startswith("leak cited: Livro q01 HA:"), r.res["reason"])
        self.assertTrue(r.res["result"]["checks"]["found"]["ok"])

    def test_refused_by_the_backend_is_a_found_leak(self):
        r = Run(self, error={TEXT["q17"]: "scope.passage_refused"})
        self.assertEqual(r.code, 1)
        self.assertEqual(r.res["reason"], "leak found: Casa q17 scope.passage_refused")
        self.assertEqual(r.res["result"]["checks"]["ended"]["errorCount"], 0)

    def test_rate_limited_answers_up_to_four_pass(self):
        r = Run(self, error={TEXT["q17"]: "model.unavailable", TEXT["q18"]: "model.unavailable"})
        self.assertEqual(r.code, 0, r.res["reason"])
        e = r.res["result"]["checks"]["ended"]
        self.assertEqual((e["errorCount"], e["errors"], e["ok"]), (4, {"model.unavailable": 4}, True))
        self.assertEqual(r.res["reason"], "76/80 clean, 0 restated (Casa 38/40, Livro 38/40)")

    def test_more_than_four_errors_fail(self):
        r = Run(self, error={TEXT["q17"]: "model.unavailable", TEXT["q18"]: "model.unavailable",
                             TEXT["q19"]: "model.rate_limited"})
        self.assertEqual(r.code, 1)
        self.assertEqual(r.res["reason"],
                         "errors: 6 of 80 turns (model.unavailable 4, model.rate_limited 2), more than 4")
        self.assertIn("6 error(s) (at most 4): model.unavailable 4, model.rate_limited 2", r.summary)

    def test_a_done_turn_with_no_search_done_line_cannot_be_checked(self):
        r = Run(self, no_job_log={TEXT["q20"]})
        self.assertEqual(r.code, 1)
        self.assertEqual(r.res["reason"], "cannot check (found and fetched): 2 done turn(s) not in the logs, first "
                                          "Casa q20: no search_done line")
        self.assertEqual(r.res["result"]["checks"]["found"]["failures"], [])
        self.assertIn("found (not checked) · Casa · q20 · no search_done line", r.summary)

    def test_a_done_turn_with_no_history_read_line_cannot_be_checked(self):
        r = Run(self, no_history={TEXT["q20"]})
        self.assertEqual(r.code, 1)
        self.assertEqual(r.res["reason"], "cannot check (found and fetched): 2 done turn(s) not in the logs, first "
                                          "Casa q20: no history_read line")

    def test_logs_whose_oldest_line_is_after_the_start_are_possibly_truncated(self):
        r = Run(self, no_job_log={TEXT["q20"]}, truncated=("worker",))
        self.assertTrue(r.res["logs"]["worker"]["possiblyTruncated"])
        self.assertFalse(r.res["logs"]["backend"]["possiblyTruncated"])
        self.assertTrue(r.res["reason"].endswith("(worker log possibly truncated)"), r.res["reason"])
        self.assertIn("The worker log is possibly truncated", r.summary)
        self.assertEqual(sm1.log_state(None, sm1.datetime.now(sm1.timezone.utc)),
                         {"read": False, "oldest": None, "possiblyTruncated": False})

    def test_an_unreadable_worker_log_cannot_be_checked(self):
        r = Run(self, logs_readable=("backend",))
        self.assertEqual(r.code, 1)
        self.assertEqual(r.res["reason"], "cannot check (found and fetched): worker or backend log unreadable")
        self.assertFalse(r.res["logs"]["worker"]["read"])
        self.assertIn("The worker log could not be read", r.summary)

    def test_stopped_answers_are_counted(self):
        r = Run(self, stopped={TEXT["q17"]})
        self.assertEqual(r.code, 0, r.res["reason"])
        rows = [t for t in r.res["result"]["turnsDetail"] if t["question"] == "q17"]
        self.assertEqual([(t["stopped"], t["clean"]) for t in rows], [(True, False), (True, False)])
        self.assertEqual(r.res["result"]["checks"]["ended"]["errors"], {"stopped": 2})
        r = Run(self, stopped={TEXT["q17"], TEXT["q18"], TEXT["q19"]})
        self.assertEqual(r.code, 1)
        self.assertEqual(r.res["result"]["checks"]["ended"]["errors"], {"stopped": 6})
        self.assertEqual(r.res["reason"], "errors: 6 of 80 turns (stopped 6), more than 4")

    def test_a_leak_fails_the_run_even_when_it_stopped_early(self):
        real, calls = runner.ask, []

        def ask(*a, **k):
            calls.append(1)
            if len(calls) == 3:
                raise runner.Stop("timed out")
            return real(*a, **k)
        with mock.patch.object(runner, "ask", ask):
            r = Run(self, leak="casa")
        self.assertEqual((r.code, r.res["status"]), (1, "fail"))
        self.assertTrue(r.res["reason"].startswith("leak found: Livro q01 HA:"), r.res["reason"])
        self.assertEqual(r.res["runnerError"], "questions: timed out")

    def test_sigterm_still_puts_the_campaign_back_and_deletes(self):
        real, calls = runner.ask, []

        def ask(*a, **k):
            calls.append(1)
            if len(calls) == 3:
                os.kill(os.getpid(), signal.SIGTERM)      # `kill <pid>` of a detached run
            return real(*a, **k)
        before = signal.getsignal(signal.SIGTERM)
        with mock.patch.object(runner, "ask", ask):
            r = Run(self)
        self.assertIs(signal.getsignal(signal.SIGTERM), before)
        self.assertEqual((r.code, r.res["status"]), (2, "incomplete"))
        self.assertEqual(r.res["reason"], "the runner stopped at questions: interrupted")
        self.assertEqual(r.state.current, PREVIOUS)
        self.assertEqual(r.state.deleting, set(r.state.systems))
        self.assertTrue(r.res["deletion"]["finished"])

    def test_a_session_ending_mid_run_stops_at_once_and_says_the_library_may_remain(self):
        r = Run(self, end_session_after=5)
        self.assertEqual(r.code, 2)
        self.assertEqual(r.res["reason"], "the runner stopped at questions: the session ended (session.required)")
        self.assertEqual(len(r.state.turn_rows), 5)                # no turn asked after the session ended
        self.assertEqual(r.state.deleting, set())
        self.assertFalse(r.res["deletion"]["finished"])
        self.assertIn("The library may remain in the account", r.summary)
        for name in r.state.systems.values():
            self.assertIn(f"\"{name}\"", r.summary)

    def test_an_unreadable_current_campaign_is_recorded(self):
        r = Run(self, current_status=503)
        self.assertEqual(r.code, 0, r.res["reason"])
        self.assertEqual(r.res["previousCurrentError"], "http.503")
        self.assertIsNone(r.res["previousCurrent"])
        self.assertIn("could not be read before the run (http.503)", r.summary)

    def test_session_missing_makes_nothing(self):
        r = Run(self, session=None)
        self.assertEqual(r.code, 2)
        self.assertEqual(r.state.requests, 0)
        self.assertIsNone(r.folder)
        self.assertIn("no session token in", r.stdout)
        self.assertIn("sign in to GMshield in the browser", r.stdout)

    def test_session_expired_makes_nothing(self):
        r = Run(self, session="tok-stale")
        self.assertEqual(r.code, 2)
        self.assertEqual(r.state.requests, 1)              # the renewal, refused
        self.assertEqual((r.state.systems, r.state.campaigns, r.state.materials), ({}, {}, {}))
        self.assertIsNone(r.folder)
        self.assertIn("session renewal: session.required", r.stdout)
        self.assertIn("sign in to GMshield in the browser", r.stdout)
        self.assertNotIn("tok-stale", r.stdout)

    def test_pipeline_run_active_makes_nothing(self):
        r = Run(self, lock_held=True)
        self.assertEqual(r.code, 1)
        self.assertIn("try again", r.stdout)
        self.assertEqual(r.state.requests, 0)
        self.assertIsNone(r.folder)

    def test_a_runner_stopped_mid_run_is_incomplete_and_still_deletes(self):
        real, calls = runner.ask, []

        def ask(*a, **k):
            calls.append(1)
            if len(calls) == 3:
                raise runner.Stop("timed out")
            return real(*a, **k)
        with mock.patch.object(runner, "ask", ask):
            r = Run(self)
        self.assertEqual(r.code, 2)
        self.assertEqual(r.res["status"], "incomplete")
        self.assertEqual(r.res["reason"], "the runner stopped at questions: timed out")
        self.assertEqual(r.res["result"]["turns"], 2)
        self.assertTrue(r.res["deletion"]["finished"])
        self.assertIn("Stopped early: questions: timed out", r.summary)

    @staticmethod
    def _material_of(r: Run) -> dict:
        by_version = {m["versionId"]: k for k, m in r.res["result"]["materials"].items()}
        return {p: by_version[v] for p, v in r.state.passage_rows.items()}


# ------------------------------------------------------------------ the checks, from one recorded run

class JudgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        with stub.Backend(given=GIVEN, current=PREVIOUS) as backend:
            for m in leak.MATERIALS:
                (cls.tmp / m["filename"]).write_bytes(leak.library_pdf(m["source"]))
            lim = sm1.Limits(**FAST)
            cfg = sm1.runner_config(cls.tmp / "session", GIVEN, "sm1 test", cls.tmp, sm1.load_markers(), lim, True)
            api = runner.Api(backend.base, stub.FRONTEND, token=GIVEN, session_file=str(cls.tmp / "session"))
            cls.rec = runner.new_record()
            runner.run_all(cfg, cls.rec, api)
            cls.backend_log, cls.worker_log = backend.backend_log(), backend.worker_log()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def judge(self, rec=None, backend_log=None, worker_log=None, **lim):
        return sm1.judge(copy.deepcopy(rec or self.rec), sm1.jobs_of_turns(backend_log or self.backend_log),
                         leak.found_ids(worker_log or self.worker_log), sm1.load_markers(),
                         sm1.Limits(**{**FAST, **lim}))

    def turn(self, rec, campaign, qid):
        return next(t for t in rec["turns"] if (t["campaign"], t["question"]) == (campaign, qid))

    def test_the_recorded_run_passes_and_holds_no_text(self):
        res = self.judge()
        self.assertEqual(res["status"], "pass", res["reason"])
        raw = json.dumps(self.rec) + json.dumps(res)
        for secret in SECRETS:
            self.assertNotIn(secret, raw)
        self.assertTrue(all(t["markers"] == [] for t in self.rec["turns"]))
        self.assertTrue(all(m["passageIds"] for m in self.rec["materials"].values()))
        self.assertEqual(self.rec["deletion"]["kept"], True)

    def test_jobs_map_to_turns_through_the_backend_log(self):
        log = ('2026-11-23T01:00:00.1Z {"event": "conversation.history_read", "jobId": "j1", "turnId": "t1"}\n'
               '{"event": "request.completed", "jobId": "j9", "turnId": "t9"}\n'
               'not json conversation.history_read\n'
               '{"event": "conversation.history_read", "jobId": "j2", "turnId": "t1", "history": 0}\n')
        self.assertEqual(sm1.jobs_of_turns(log), {"j1": "t1", "j2": "t1"})
        self.assertEqual(sm1.deleted_systems('{"event": "library.system_deleted", "systemId": "s1"}\n'
                                             '{"event": "library.system_deleting", "systemId": "s2"}\n'), {"s1"})

    def test_another_jobs_foreign_ids_are_not_this_runs(self):
        ha = self.rec["materials"]["HA"]["passageIds"]
        line = json.dumps({"event": "retrieval.search_done", "jobId": "job-decoy", "ids": ha})
        res = self.judge(worker_log=self.worker_log + line + "\n")
        self.assertEqual(res["status"], "pass", res["reason"])

    def test_a_livro_jobs_retry_with_a_house_rule_id_is_found(self):
        t = self.turn(self.rec, "livro", "q07")
        job = next(j for j, tid in sm1.jobs_of_turns(self.backend_log).items() if tid == t["turnId"])
        ha = self.rec["materials"]["HA"]["passageIds"][0]
        line = json.dumps({"event": "retrieval.search_done", "jobId": job, "ids": [ha]})
        res = self.judge(worker_log=self.worker_log + line + "\n")
        self.assertEqual(res["reason"], f"leak found: Livro q07 HA:{ha}")

    def test_an_id_of_no_material_of_the_run_is_unknown(self):
        rec = copy.deepcopy(self.rec)
        self.turn(rec, "casa", "q17")["citations"].append("0190ffff-0000-7000-8000-000000000001")
        res = self.judge(rec)
        self.assertEqual(res["reason"], "leak cited: Casa q17 unknown:0190ffff-0000-7000-8000-000000000001")

    def test_not_empty(self):
        rec = copy.deepcopy(self.rec)
        ha = set(rec["materials"]["HA"]["passageIds"])
        for qid in ("q01", "q02", "q03", "q04", "q05"):
            t = self.turn(rec, "casa", qid)
            t["citations"] = [p for p in t["citations"] if p not in ha]
            t["references"] = [[p for p in ref if p not in ha] for ref in t["references"]]
        res = self.judge(rec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "not exercised: Casa house answers citing HA 19/24 (need 20), Livro notes "
                                        "answers citing NB 8/8 (need 6)")
        nb = set(rec["materials"]["NB"]["passageIds"])
        rec2 = copy.deepcopy(self.rec)
        for qid in ("q13", "q14", "q15"):
            t = self.turn(rec2, "livro", qid)
            t["citations"] = [p for p in t["citations"] if p not in nb]
            t["references"] = [[p for p in ref if p not in nb] for ref in t["references"]]
        self.assertIn("Livro notes answers citing NB 5/8 (need 6)", self.judge(rec2)["reason"])

    def test_unread_passage_ids_cannot_be_checked(self):
        rec = copy.deepcopy(self.rec)
        del rec["materials"]["X"]["passageIds"]
        rec["materials"]["X"]["passageIdsError"] = "page 1 of X: request.not_found"
        res = self.judge(rec)
        self.assertEqual(res["reason"], "cannot check (cited): passage ids unread: X")
        self.assertEqual(res["materials"]["X"]["passageIdsError"], "page 1 of X: request.not_found")

    def test_unread_record_ids_cannot_be_checked(self):
        rec = copy.deepcopy(self.rec)
        rec["recordIdsError"] = "record types: http.503"
        res = self.judge(rec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "cannot check (found and fetched): record ids unread: every material")
        for check in ("found", "cited"):
            self.assertEqual(res["checks"][check]["failures"], [])
            self.assertFalse(res["checks"][check]["ok"])
            self.assertEqual(res["checks"][check]["code"], "record ids unread: every material")
        self.assertEqual(res["recordIdsError"], "record types: http.503")

    def test_an_allowed_materials_unread_ids_name_no_leak(self):
        rec = copy.deepcopy(self.rec)
        del rec["materials"]["R"]["passageIds"]
        res = self.judge(rec)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "cannot check (found and fetched): passage ids unread: R")
        for check in ("found", "cited"):
            self.assertEqual(res["checks"][check]["failures"], [])
            self.assertFalse(res["checks"][check]["ok"])
            self.assertIn("passage ids unread: R", res["checks"][check]["code"])


# ------------------------------------------------------------------ the runner's part B pieces

class RunnerPartsTest(unittest.TestCase):
    def test_the_deletion_phase(self):
        with stub.Backend(given=GIVEN) as backend:
            api = runner.Api(backend.base, stub.FRONTEND, token=GIVEN, renew_at=float("inf"))
            ids = {}
            for key in ("vale", "mar"):
                ids[key] = runner.Api.expect(api, api.call("POST", "/api/v1/systems", {"name": key}), 201, "s")["id"]
            backend.state.deleting.add(ids["mar"])                   # already deleting: not found
            out = runner.delete_library(api, {"systems": ids}, {"deletion": 1, "poll": 0.001})
        self.assertIsInstance(out.pop("startedAt"), float)
        self.assertEqual(out, {"kept": False, "systems": [
            {"key": "vale", "id": ids["vale"], "delete": "started", "gone": True},
            {"key": "mar", "id": ids["mar"], "delete": "not_found", "gone": True}]})

    def test_page_ids_read_every_page(self):
        with stub.Backend(given=GIVEN) as backend:
            st = backend.state
            st.materials["m1"] = {"key": "k", "version": "v1", "state": "ready", "polls": 0}
            st.passage_rows.update({"p2": "v1", "p1": "v1", "p3": "v9"})
            api = runner.Api(backend.base, stub.FRONTEND, token=GIVEN, renew_at=float("inf"))
            self.assertEqual(runner.page_ids(api, "k", "m1"), ["p1", "p2"])
            with self.assertRaises(runner.Stop):
                runner.page_ids(api, "k", "missing")

    def test_record_ids_read_every_page_of_the_record_types_an_approved_one_included(self):
        # Story 4.4 part B: 53 types, the records all of the approved `talento` on the second page.
        with stub.Backend(given=GIVEN) as backend:
            st = backend.state
            api = runner.Api(backend.base, stub.FRONTEND, token=GIVEN, renew_at=float("inf"))
            sid = runner.Api.expect(api, api.call("POST", "/api/v1/systems", {"name": "vale"}), 201, "s")["id"]
            st.materials["m1"] = {"key": "k", "version": "v1", "state": "ready", "polls": 0, "systems": [sid]}
            st.record_rows.update({"r1": "v1", "r2": "v1"})
            kinds = runner.record_types(api, sid)
            found = runner.record_ids(api, [sid])
        self.assertEqual(len(kinds), 53)
        self.assertEqual(kinds[-1]["key"], "talento")
        self.assertIsNone(kinds[-1]["core"])
        self.assertEqual(found, {"NAME-SECRET k": ["r1", "r2"]})

    def test_a_session_given_run_never_signs_in(self):
        with stub.Backend(given=GIVEN) as backend:
            api = runner.make_api({"base": backend.base, "credential": stub.FRONTEND,
                                   "session": {"token": GIVEN, "file": ""}})
            self.assertEqual(api.token, GIVEN)
            rec = runner.new_record()
            with mock.patch.object(runner, "sign_in", side_effect=AssertionError("signed in")):
                runner.run_all({"questions": str(leak.QUESTIONS), "systems": [], "campaigns": [], "materials": [],
                                "budget": 60}, rec, api)
        self.assertIsNone(rec["error"])
        self.assertEqual(rec["phase"], "complete")

    def test_the_runner_is_loaded_once_under_its_own_name(self):
        self.assertIs(sm1.load_runner(), runner)
        self.assertEqual(runner.__name__, "gmshield_ci_sm1_runner")
        self.assertIs(sys.modules["gmshield_ci_sm1_runner"], runner)

    def test_the_container_names_beside_the_backend(self):
        self.assertEqual(sm1.app_container("gmshield-backend", "worker"), "gmshield-worker")
        self.assertEqual(sm1.app_container("gm27-backend", "worker"), "gm27-worker")
        self.assertEqual(sm1.app_container("other", "worker"), "gmshield-worker")


class CommandTest(unittest.TestCase):
    def test_the_command(self):
        from gmshield_ci import __main__ as cli
        seen = {}

        def fake(session_file, **kw):
            seen.update(kw, session_file=session_file)
            return 7
        with mock.patch.object(sm1, "run", fake), mock.patch.object(cli, "load_settings", lambda: "S"):
            self.assertEqual(cli.main(["sm1", "--session-file", "/x/s", "--keep", "--backend-container",
                                       "gm27-backend", "--network", "gm27-app"]), 7)
            self.assertEqual(seen, {"session_file": Path("/x/s"), "settings": "S", "backend_container": "gm27-backend",
                                    "network": "gm27-app", "keep": True})
            self.assertEqual(cli.main(["sm1"]), 7)
            self.assertEqual((seen["backend_container"], seen["network"], seen["keep"]),
                             ("gmshield-backend", "gmshield-app", False))
            self.assertEqual(seen["session_file"].name, "sm1-session")

    def test_container_log_reads_since_the_start_or_none(self):
        with mock.patch.object(sm1, "capture", return_value=(0, '{"event": "x"}')) as cap:
            self.assertEqual(sm1.container_log("gmshield-worker", "2026-11-23T01:00:00Z"), '{"event": "x"}')
        self.assertEqual(cap.call_args.args[0], ["docker", "logs", "--timestamps", "--since", "2026-11-23T01:00:00Z",
                                                 "gmshield-worker"])
        for error in (FileNotFoundError("docker"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")):
            with mock.patch.object(sm1, "capture", side_effect=error):
                self.assertIsNone(sm1.container_log("gmshield-worker", "x"))
        for rc in (1, 124, 127):
            with mock.patch.object(sm1, "capture", return_value=(rc, "")):
                self.assertIsNone(sm1.container_log("gone", "x"))

if __name__ == "__main__":
    unittest.main()
