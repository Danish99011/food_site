"""Output: human text, JSON, SARIF 2.1.0, GitHub Actions annotations."""
from __future__ import annotations

import json
import sys

from .findings import Finding, SEVERITIES, rank

_COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"


def summary_line(findings: list[Finding]) -> str:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [f"{counts[s]} {s}" for s in SEVERITIES if counts[s]]
    return ", ".join(parts) if parts else "no findings"


def text(findings: list[Finding], *, title: str = "secure-check", color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty()
    lines = [f"{title}: {summary_line(findings)}"]
    fixes: dict[str, str] = {}
    for f in findings:
        c = _COLOR.get(f.severity, "") if color else ""
        r = _RESET if color else ""
        where = f.path + (f":{f.line}" if f.line else "")
        if f.commit:
            where += f" @ {f.commit}"
        extra = []
        if f.preview:
            extra.append(f"value {f.preview}")
        if f.fingerprint:
            extra.append(f"fp {f.fingerprint}")
        if f.tags:
            extra.append(",".join(f.tags))
        tail = f"  [{'; '.join(extra)}]" if extra else ""
        lines.append(f"  {c}{f.severity.upper():8s}{r} {f.rule:32s} {where}\n           {f.message}{tail}")
        if f.fix and f.rule not in fixes:
            fixes[f.rule] = f.fix
    if fixes:
        lines.append("")
        lines.append("What to do:")
        for rule, fix in fixes.items():
            lines.append(f"  - {rule}: {fix}")
    return "\n".join(lines)


def as_json(findings: list[Finding], meta: dict | None = None) -> str:
    return json.dumps({"summary": summary_line(findings), "meta": meta or {},
                       "findings": [f.to_dict() for f in findings]}, indent=2)


def github_annotations(findings: list[Finding]) -> str:
    """Workflow commands that GitHub renders inline on the PR/commit."""
    out = []
    for f in findings:
        level = "error" if rank(f.severity) >= rank("high") else "warning" if f.severity == "medium" else "notice"
        msg = f"[{f.rule}] {f.message}" + (f" (fp {f.fingerprint})" if f.fingerprint else "")
        msg = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        loc = f"file={f.path}" + (f",line={f.line}" if f.line else "")
        out.append(f"::{level} {loc},title=secure-check::{msg}")
    out.append(f"::notice title=secure-check::{summary_line(findings)}")
    return "\n".join(out)


def sarif(findings: list[Finding], version: str) -> str:
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(f.rule, {
            "id": f.rule, "shortDescription": {"text": f.message[:120]},
            "help": {"text": f.fix or ""},
            "defaultConfiguration": {"level": "error" if rank(f.severity) >= rank("high") else "warning"},
        })
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.path}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule,
            "level": "error" if rank(f.severity) >= rank("high") else "warning" if f.severity == "medium" else "note",
            "message": {"text": f.message + (f" (fingerprint {f.fingerprint})" if f.fingerprint else "")},
            "locations": [loc],
            "partialFingerprints": {"secure-check/v1": f.fingerprint or f"{f.rule}:{f.path}:{f.line}"},
            "properties": {"severity": f.severity, "commit": f.commit, "tags": f.tags},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "secure-check", "version": version,
                                       "informationUri": "https://github.com/Danish99011/Secure-check",
                                       "rules": list(rules.values())}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)


def render(findings: list[Finding], fmt: str, *, version: str = "0", meta: dict | None = None, title: str = "secure-check") -> str:
    if fmt == "json":
        return as_json(findings, meta)
    if fmt == "sarif":
        return sarif(findings, version)
    if fmt == "github":
        return github_annotations(findings) + "\n" + text(findings, title=title, color=False)
    return text(findings, title=title)
