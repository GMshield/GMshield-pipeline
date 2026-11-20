"""The end-to-end test's driver (Story 2.9): a real Chromium walks the five steps through the frontend's UI.

Run by the pipeline (gmshield_ci/e2e.py) in Playwright's Python image, inside the frontend container's network
namespace, so the site is http://localhost:3000 and its `__Host-` Secure cookies work over plain HTTP:

    python -I /e2e/driver.py /in/config.json

config.json (written by the pipeline): {"base", "pdf", "question", "username", "messages", "out", "budget",
"limits": {step: seconds}}. `messages` is the frontend's own en.json at the tested commit: every label the driver
looks for comes from it, so a reworded label never breaks the test, only a renamed key does.

Steps, each with its own time limit (and never past the whole budget), recorded in <out>/result.json as
{step, status, seconds, error}: sign_in, upload, accept, ask, open_reference. The first failure stops the run (later
steps are not_run) and leaves <out>/<step>-failed.png. A Content-Security-Policy violation the browser reports during a
step fails that step. Exit status 0 only when every step passed.

result.json and the log hold only the steps, timings, errors and counts, never answer or passage text; a failure
screenshot shows only the test's invented PDF and the fake model's answer, never library text.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

STEPS = ("sign_in", "upload", "accept", "ask", "open_reference")
DEFAULT_LIMITS = {"sign_in": 180, "upload": 720, "accept": 600, "ask": 300, "open_reference": 180}
POLL = 1.0


class StepFailed(Exception):
    pass


class Messages:
    """The frontend's en.json, by dotted key."""

    def __init__(self, path: str):
        self.data = json.loads(Path(path).read_text(encoding="utf-8"))

    def __call__(self, key: str, **params) -> str:
        node = self.data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                raise StepFailed(f"the frontend has no message {key}")
            node = node[part]
        if not isinstance(node, str):
            raise StepFailed(f"the frontend's message {key} is not a text")
        return re.sub(r"\{(\w+)\}", lambda m: str(params.get(m.group(1), m.group(0))), node)

    def pattern(self, key: str) -> re.Pattern:
        """The whole message, anchored, with each placeholder as a number (digits, with group separators)."""
        parts = re.split(r"\{\w+\}", self(key))
        return re.compile("^" + r"\d[\d,.]*".join(re.escape(x) for x in parts) + "$")

    def prefix(self, key: str) -> str:
        """The text before the message's first placeholder."""
        return self(key).split("{", 1)[0].strip()


class Driver:
    def __init__(self, cfg: dict, page, m: Messages, out: Path):
        self.cfg, self.page, self.m, self.out = cfg, page, m, out
        self.base = cfg["base"].rstrip("/")
        self.csp: list[str] = []
        self.material_name = ""
        self.material_url = ""
        self.reference = None
        self.deadline = 0.0

    # -- helpers
    def left(self) -> float:
        return self.deadline - time.monotonic()

    def ms(self, cap: float | None = None) -> float:
        """Milliseconds left in the step (at least 1 s, for Playwright)."""
        s = self.left() if cap is None else min(cap, self.left())
        if s <= 0:
            raise StepFailed("time limit reached")
        return max(1000.0, s * 1000)

    def until(self, check, what: str, every: float = POLL, reload_every: float | None = None):
        """Calls `check` until it returns something truthy (that value) or the step's time runs out."""
        last_reload = time.monotonic()
        while True:
            value = check()
            if value:
                return value
            if self.left() <= 0:
                raise StepFailed(f"{what} within the step's time limit")
            if reload_every is not None and time.monotonic() - last_reload >= reload_every:
                self.page.reload(wait_until="load", timeout=self.ms(60))
                last_reload = time.monotonic()
            time.sleep(min(every, max(self.left(), 0.05)))

    def visible(self, locator) -> bool:
        try:
            return locator.count() > 0 and locator.first.is_visible()
        except Exception:  # noqa: BLE001 - a page that navigates meanwhile
            return False

    def go(self, path: str) -> None:
        self.page.goto(self.base + path, wait_until="load", timeout=self.ms(60))

    # -- the steps
    def sign_in(self) -> None:
        m, page = self.m, self.page
        self.go("/")
        page.get_by_role("button", name=m("signIn.google"), exact=True).click(timeout=self.ms())
        page.wait_for_url(re.compile(r"/sign-in/username"), timeout=self.ms())
        page.get_by_label(m("username.label"), exact=True).fill(self.cfg["username"], timeout=self.ms())
        page.get_by_label(m("username.terms"), exact=True).check(timeout=self.ms())
        page.get_by_role("button", name=m("username.submit"), exact=True).click(timeout=self.ms())
        page.wait_for_url(re.compile(r"/questions(?:[?#].*)?$"), timeout=self.ms())
        # The backend has just started: its first answers can outlast the frontend's backend timeout, so this first
        # page may render "service unavailable" with no composer. Reload until it appears, as a GM would.
        composer = page.get_by_label(m("conversation.composer.label"), exact=True)
        self.until(lambda: self.visible(composer), "the questions screen never showed its composer", every=2.0,
                   reload_every=10.0)

    def upload(self) -> None:
        m, page = self.m, self.page
        pdf = Path(self.cfg["pdf"])
        page.get_by_role("button", name=m("shell.entries.addFile"), exact=True).click(timeout=self.ms())
        dialog = page.get_by_role("dialog", name=m("upload.dialog.title"), exact=True)
        dialog.wait_for(timeout=self.ms())
        with page.expect_file_chooser(timeout=self.ms()) as chooser:
            dialog.get_by_role("button", name=m("upload.dialog.files.choose"), exact=True).click(timeout=self.ms())
        chooser.value.set_files(str(pdf))
        english = dialog.get_by_role("radio", name=re.compile("^" + re.escape(m("upload.dialog.language.en.label"))))
        send = dialog.get_by_role("button", name=m("upload.dialog.send"), exact=True)
        nxt = dialog.get_by_role("button", name=m("upload.dialog.next"), exact=True)
        for _ in range(8):
            if english.count() > 0:
                english.check(timeout=self.ms())
            if send.count() > 0:
                send.click(timeout=self.ms())
                break
            self.until(lambda: nxt.count() > 0 and nxt.is_enabled(), "the file was not accepted by the dialog")
            nxt.click(timeout=self.ms())
        else:
            raise StepFailed("the guided upload never reached its Send button")
        page.keyboard.press("Escape")      # "you can close this window: the files keep going"
        link = page.get_by_role("link", name=pdf.name, exact=True)
        self.until(lambda: self.visible(link), "the upload never became a material (no link in the tray)")
        link.first.click(timeout=self.ms())
        page.wait_for_url(re.compile(r"/files/[^/?#]+(?:[?#].*)?$"), timeout=self.ms())
        self.material_url = page.url
        accept = page.get_by_role("button", name=m("material.actions.accept"), exact=True)
        retry = page.get_by_role("button", name=m("material.actions.retry"), exact=True)

        def reviewed():
            if self.visible(retry):
                raise StepFailed("the material failed to process")
            return self.visible(accept)
        self.until(reviewed, "the material did not reach review", every=2.0, reload_every=60.0)
        self.material_name = page.get_by_role("heading", level=1).first.inner_text(timeout=self.ms()).strip()

    def accept(self) -> None:
        m, page = self.m, self.page
        page.get_by_role("button", name=m("material.actions.accept"), exact=True).click(timeout=self.ms())
        accept = page.get_by_role("button", name=m("material.actions.accept"), exact=True)
        ready = page.get_by_text(m("material.state.ready"), exact=True)
        # The actions' refusal line, inside the material actions' container (the upload tray has alerts of its own).
        alert = page.get_by_role("form", name=m("material.actions.label"), exact=True).locator(
            "xpath=..").locator("p[role='alert']")

        def accepted():
            if self.visible(alert) and alert.first.inner_text().strip():
                raise StepFailed(f"the accept was refused: {alert.first.inner_text().strip()[:200]}")
            return not self.visible(accept) and self.visible(ready)
        self.until(accepted, "the material was not ready after Accept", every=2.0, reload_every=30.0)
        self.go("/questions")
        pending = page.get_by_text(re.compile("^" + re.escape(m.prefix("notice.indexing"))))
        # The final failure only: the retrying line ("...; trying again in a few minutes.") is not one.
        failed = page.get_by_text(m.pattern("notice.indexingFailed")).or_(
            page.get_by_text(m.pattern("notice.indexingFailedOne")))
        empty = page.get_by_test_id("conversation-empty")
        calm = {"since": None}

        def indexed():
            if self.visible(failed):
                raise StepFailed(f"indexing failed: {failed.first.inner_text().strip()[:200]}")
            if self.visible(pending) or self.visible(empty):
                calm["since"] = None
                return False
            calm["since"] = calm["since"] or time.monotonic()
            return time.monotonic() - calm["since"] >= 6.0     # gone, and still gone a moment later
        self.until(indexed, "indexing did not finish (the indexing notice is still there)", every=2.0,
                   reload_every=20.0)

    def ask(self) -> None:
        m, page = self.m, self.page
        box = page.get_by_label(m("conversation.composer.label"), exact=True)
        box.fill(self.cfg["question"], timeout=self.ms())
        page.get_by_role("button", name=m("conversation.composer.send"), exact=True).click(timeout=self.ms())
        turns = page.get_by_role("list", name=m("conversation.turns"), exact=True)
        refs = turns.get_by_role("list", name=m("conversation.references"), exact=True).get_by_role("button")
        silent = turns.get_by_text(m("conversation.silent"), exact=True)
        retry = turns.get_by_role("button", name=m("conversation.retry"), exact=True)
        alert = page.get_by_test_id("conversation-alert")

        def answered():
            said = alert.inner_text().strip() if alert.count() else ""
            if said:
                raise StepFailed(f"the answer failed: {said[:200]}")
            if self.visible(silent):
                raise StepFailed("the answer is the silent answer (no reference)")
            if self.visible(retry):
                raise StepFailed("the answer failed (Try again is offered)")
            return refs.count() > 0
        self.until(answered, "the answer did not complete with references")
        names = [refs.nth(i).inner_text().strip() for i in range(refs.count())]
        known = {x for x in (self.material_name, Path(self.cfg["pdf"]).name) if x}
        mine = [i for i, n in enumerate(names) if any(x in n for x in known)]
        if not mine:
            raise StepFailed(f"{len(names)} reference(s), none to the uploaded material")
        self.reference = refs.nth(mine[0])

    def open_reference(self) -> None:
        m, page = self.m, self.page
        if self.reference is None:
            raise StepFailed("no reference to open")
        picture = re.compile(r"/api/v1/turns/[^/]+/references/\d+/pages/\d+/picture(?:\?.*)?$")
        with page.expect_response(lambda r: bool(picture.search(r.url)), timeout=self.ms()) as answer:
            self.reference.click(timeout=self.ms())
        response = answer.value
        kind = (response.headers.get("content-type") or "").split(";")[0].strip()
        if response.status != 200 or not kind.startswith("image/"):
            raise StepFailed(f"the page picture did not load (HTTP {response.status}, {kind or 'no type'})")
        view = page.get_by_role("dialog").filter(has=page.get_by_role("button", name=m("conversation.close"),
                                                                      exact=True))
        view.first.wait_for(timeout=self.ms())
        failed = view.get_by_text(m("pageView.loadFailed"), exact=True)
        if self.visible(failed):
            raise StepFailed("the source view says the page could not be loaded")
        view.first.locator("image").first.wait_for(state="attached", timeout=self.ms())
        view.first.locator("[data-cited]").first.wait_for(state="attached", timeout=self.ms())


def run_steps(d, steps, limits: dict, end: float, screenshot) -> dict:
    """Runs `steps` (names of `d`'s methods) in order, each until its limit and never past `end` (monotonic time).

    A step fails on any exception, or when `d.csp` grew during it (a Content-Security-Policy violation the browser
    reported); a failed step calls `screenshot(step)` (whose own failure is ignored) and stops the run, leaving the
    later steps not_run. When `d.page` exists, its default timeout follows each step's limit. Needs no Playwright.
    Returns the result: {"steps": [{step, status, seconds, error}], "passed", "csp_violations"}.
    """
    records = [{"step": s, "status": "not_run", "seconds": 0.0, "error": None} for s in steps]
    for rec in records:
        t0 = time.monotonic()
        d.deadline = min(end, t0 + float(limits.get(rec["step"], 300)))
        page = getattr(d, "page", None)
        if page is not None:
            page.set_default_timeout(max(1000.0, (d.deadline - t0) * 1000))
        seen = len(d.csp)
        try:
            getattr(d, rec["step"])()
            if len(d.csp) > seen:
                raise StepFailed(f"Content-Security-Policy violation: {d.csp[seen]}")
            rec["status"] = "passed"
        except Exception as e:  # noqa: BLE001 - every failure is the step's
            rec["status"] = "failed"
            why = str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__
            if not isinstance(e, StepFailed):
                why = f"{type(e).__name__}: {why}"
            if time.monotonic() >= end:
                why = f"timed out (the whole test's budget): {why}"
            rec["error"] = why[:500]
            try:
                screenshot(rec["step"])
            except Exception:  # noqa: BLE001 - a screenshot never hides the failure
                pass
        rec["seconds"] = round(time.monotonic() - t0, 1)
        if rec["status"] != "passed":
            break
    return {"steps": records, "passed": all(r["status"] == "passed" for r in records), "csp_violations": len(d.csp)}


def run(cfg: dict) -> dict:
    """Runs the steps in Chromium; returns the result written to result.json."""
    from playwright.sync_api import sync_playwright     # only in Playwright's image

    out = Path(cfg["out"])
    limits = {**DEFAULT_LIMITS, **(cfg.get("limits") or {})}
    end = time.monotonic() + float(cfg.get("budget", 1200))
    m = Messages(cfg["messages"])
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--disable-dev-shm-usage"])
        try:
            context = browser.new_context(locale="en-US", viewport={"width": 1440, "height": 900},
                                          accept_downloads=False)
            page = context.new_page()
            d = Driver(cfg, page, m, out)
            page.expose_function("__e2eCsp", lambda text: d.csp.append(str(text)[:300]))
            context.add_init_script(
                "document.addEventListener('securitypolicyviolation', (e) => {"
                " try { window.__e2eCsp(`${e.disposition} ${e.effectiveDirective} ${e.blockedURI}`); } catch (_) {} },"
                " true);")
            page.on("console", lambda msg: d.csp.append(msg.text[:300])
                    if "Content Security Policy" in msg.text else None)
            return run_steps(d, STEPS, limits, end, lambda step: page.screenshot(
                path=str(out / f"{step}-failed.png"), full_page=True, timeout=15000))
        finally:
            browser.close()


def main(argv: list[str]) -> int:
    cfg = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    out = Path(cfg["out"])
    try:
        result = run(cfg)
    except Exception as e:  # noqa: BLE001 - the browser could not start, the messages are missing...
        result = {"steps": [{"step": s, "status": "failed" if i == 0 else "not_run", "seconds": 0.0,
                             "error": f"driver: {type(e).__name__}: {str(e)[:300]}" if i == 0 else None}
                            for i, s in enumerate(STEPS)], "passed": False}
    (out / "result.json").write_text(json.dumps(result, indent=2))
    for s in result["steps"]:
        print(f"{s['step']}: {s['status']} ({s['seconds']}s){' - ' + s['error'] if s['error'] else ''}", flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
