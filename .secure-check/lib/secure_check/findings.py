"""The one data type every check produces."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}


def rank(severity: str) -> int:
    return _RANK.get(severity, -1)


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    message: str
    line: int | None = None
    fingerprint: str | None = None   # sha256 prefix of the secret, never the secret
    preview: str | None = None       # redacted, e.g. "ya29…(254 chars)"
    commit: str | None = None        # short sha when found in history
    fix: str | None = None           # what to do about it, in plain words
    tags: list[str] = field(default_factory=list)

    def key(self) -> tuple:
        return (self.rule, self.path, self.line, self.fingerprint, self.commit)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], "")}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Same rule at the same place is one finding; keep the highest severity."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        k = f.key()
        if k not in best or rank(f.severity) > rank(best[k].severity):
            best[k] = f
    return sorted(best.values(), key=lambda f: (-rank(f.severity), f.path, f.line or 0, f.rule))


def at_or_above(findings: list[Finding], threshold: str) -> list[Finding]:
    t = rank(threshold)
    return [f for f in findings if rank(f.severity) >= t]
