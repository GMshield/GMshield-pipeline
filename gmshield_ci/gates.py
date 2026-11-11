"""Turn scanner reports into counts, and judge the counts against gates.toml."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _load(path: Path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------------ parsers

def parse_gitleaks(path: Path) -> dict:
    data = _load(path) or []
    rules = Counter(f.get("RuleID", "?") for f in data)
    return {"findings": len(data), "rules": dict(rules.most_common(10)),
            "where": [f"{f.get('File', '?')}:{f.get('StartLine', '?')} ({f.get('Commit', '')[:8]})" for f in data[:20]]}


def _semgrep_level(sev: str) -> str:
    s = (sev or "").upper()
    if s in ("ERROR", "CRITICAL", "HIGH"):
        return "high"
    if s in ("WARNING", "MEDIUM"):
        return "medium"
    return "low"


def _semgrep_scan_error(e: dict, root: str) -> tuple[str | None, str, list[int]]:
    """(file, kind, lines) of one entry in Semgrep's `errors` list.

    `type` is a plain name ("Syntax error", "Timeout") or a pair such as
    ["PartialParsing", [locations]]; `spans` or those locations say where.
    """
    kind = e.get("type")
    spans = e.get("spans") or []
    if isinstance(kind, list):
        if not spans and len(kind) > 1 and isinstance(kind[1], list):
            spans = kind[1]
        kind = kind[0] if kind else None
    spans = [sp for sp in spans if isinstance(sp, dict)]
    file = e.get("path") or next((sp.get("file") or sp.get("path") for sp in spans), None)
    if file and file.startswith(root):
        file = file[len(root):]
    lines = sorted({(sp.get("start") or {}).get("line") for sp in spans} - {None})
    return file, str(kind or e.get("message") or "error"), lines


def _semgrep_warnings(errors: list, root: str, limit: int = 15) -> tuple[int, list[str]]:
    """One warning per file Semgrep did not fully scan: (number of files, warning texts)."""
    per_file: dict[str | None, dict] = {}
    for e in errors:
        file, kind, lines = _semgrep_scan_error(e if isinstance(e, dict) else {"message": str(e)}, root)
        entry = per_file.setdefault(file, {"kinds": [], "lines": set()})
        if kind not in entry["kinds"]:
            entry["kinds"].append(kind)
        entry["lines"].update(lines)
    out = []
    for file, entry in per_file.items():
        where = f", line{'s' if len(entry['lines']) > 1 else ''} {', '.join(map(str, sorted(entry['lines'])))}" \
            if entry["lines"] else ""
        out.append(f"not fully scanned: {file or 'file not named by Semgrep'} ({'; '.join(entry['kinds'])}{where})")
    if len(out) > limit:
        out = out[:limit] + [f"... and {len(out) - limit} more file(s), see semgrep.json"]
    return len(per_file), out


def parse_semgrep(path: Path, root: str = "/src/") -> dict:
    """Counts by severity, plus a warning for every file Semgrep could not fully scan.

    Semgrep exits successfully when it cannot parse part of a file (for example syntax newer than
    its parser), so that code would otherwise pass the gate unread. The warnings do not block.
    """
    data = _load(path)
    levels = Counter(_semgrep_level(r.get("extra", {}).get("severity", "")) for r in data.get("results", []))
    top = Counter(r.get("check_id", "?").rsplit(".", 1)[-1] for r in data.get("results", []))
    errors = data.get("errors") or []
    files, warnings = _semgrep_warnings(errors, root)
    return {"high": levels["high"], "medium": levels["medium"], "low": levels["low"],
            "scan_errors": len(errors), "unscanned_files": files, "warnings": warnings,
            "top_rules": dict(top.most_common(10))}


def parse_trivy(path: Path) -> dict:
    data = _load(path)
    vuln, fixable, misconf = Counter(), Counter(), Counter()
    top = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN")
            vuln[sev] += 1
            if v.get("FixedVersion"):
                fixable[sev] += 1
            if sev in ("CRITICAL", "HIGH") and len(top) < 15:
                top.append(f"{sev} {v.get('VulnerabilityID')} {v.get('PkgName')} {v.get('InstalledVersion')}"
                           f" -> {v.get('FixedVersion') or 'no fix'}")
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") == "FAIL":
                misconf[m.get("Severity", "UNKNOWN")] += 1
                if m.get("Severity") in ("CRITICAL", "HIGH") and len(top) < 15:
                    top.append(f"{m.get('Severity')} {m.get('ID')} {m.get('Title')} ({res.get('Target')})")
    return {"vuln": {s: vuln[s] for s in SEVERITIES}, "vuln_fixable": {s: fixable[s] for s in SEVERITIES},
            "misconfig": {s: misconf[s] for s in SEVERITIES}, "top": top}


_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def parse_zap(path: Path, ignore_ids: set[str] = frozenset()) -> dict:
    data = _load(path)
    counts, alerts, ignored = Counter(), [], 0
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            if str(a.get("pluginid")) in ignore_ids:
                ignored += 1
                continue
            risk = _RISK.get(str(a.get("riskcode")), "info")
            counts[risk] += 1
            alerts.append({"id": a.get("pluginid"), "name": a.get("alert") or a.get("name"),
                           "risk": risk, "instances": int(a.get("count", 0) or 0)})
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    alerts.sort(key=lambda a: order[a["risk"]])
    return {"high": counts["high"], "medium": counts["medium"], "low": counts["low"],
            "info": counts["info"], "ignored": ignored, "alerts": alerts[:25]}


# ------------------------------------------------------------------ judging

def _over(label: str, value: int, limit) -> list[str]:
    return [f"{label} {value} > {limit}"] if limit is not None and value > int(limit) else []


def judge(kind: str, outcome: str, metrics: dict, gates: dict) -> tuple[str, str, list[str]]:
    """Return (status, threshold text, reasons). outcome: ok | error | skipped.

    status: passed | failed | skipped
    """
    g = gates.get(kind, {})
    if outcome == "skipped":
        if kind == "unit_tests" and g.get("required"):
            return "failed", "tests required", ["no test stage, but unit tests are required"]
        return "skipped", "-", []
    if outcome == "error":
        if gates.get("fail_on_error", True):
            return "failed", "scanner must finish", [metrics.get("error", "scanner error")]
        return "passed", "errors tolerated", [metrics.get("error", "scanner error")]

    reasons: list[str] = []
    if kind == "unit_tests":
        threshold = "all tests pass"
        if metrics.get("exit_code", 0) != 0:
            reasons.append(f"tests failed (exit {metrics.get('exit_code')})")
    elif kind == "secrets":
        threshold = f"findings <= {g.get('max_findings', 0)}"
        reasons += _over("leaked secrets", metrics["findings"], g.get("max_findings", 0))
    elif kind == "sast":
        threshold = f"high <= {g.get('max_high', 0)}, medium <= {g.get('max_medium', 25)}"
        reasons += _over("high", metrics["high"], g.get("max_high", 0))
        reasons += _over("medium", metrics["medium"], g.get("max_medium", 25))
    elif kind == "sonar":
        threshold = f"SonarQube quality gate '{g.get('quality_gate', 'GMshield')}' is OK"
        if metrics.get("status") != "OK":
            reasons += metrics.get("failed") or [f"quality gate status {metrics.get('status', 'NONE')}"]
            if metrics.get("hotspots_to_review"):
                reasons.append(f"{metrics['hotspots_to_review']} security hotspot(s) await review in SonarQube")
    elif kind == "promotion":
        threshold = "same tree passed develop"
        if not metrics.get("promoted"):
            reasons.append("this exact code has not passed the develop quality gate; merge from develop")
    elif kind in ("sca", "image"):
        if kind == "image" and metrics.get("build_exit", 0) != 0:
            return "failed", "image must build", [f"image build failed (exit {metrics['build_exit']})"]
        fix = g.get("only_fixable", True)
        src = metrics["vuln_fixable"] if fix else metrics["vuln"]
        threshold = (f"critical <= {g.get('max_critical', 0)}, high <= {g.get('max_high', 0)}"
                     f"{' (fixable)' if fix else ''}")
        reasons += _over("critical", src["CRITICAL"], g.get("max_critical", 0))
        reasons += _over("high", src["HIGH"], g.get("max_high", 0))
    elif kind == "iac":
        m = metrics["misconfig"]
        threshold = f"critical <= {g.get('max_critical', 0)}, high <= {g.get('max_high', 0)}"
        reasons += _over("critical", m["CRITICAL"], g.get("max_critical", 0))
        reasons += _over("high", m["HIGH"], g.get("max_high", 0))
    elif kind in ("dast_develop", "dast_main"):
        threshold = f"high <= {g.get('max_high', 0)}, medium <= {g.get('max_medium', 5)}"
        reasons += _over("high alerts", metrics["high"], g.get("max_high", 0))
        reasons += _over("medium alerts", metrics["medium"], g.get("max_medium", 5))
    else:
        threshold = "-"
    return ("failed" if reasons else "passed"), threshold, reasons
