"""Tamper evidence for the files that must not change without the owner.

Two mechanisms:

* **Baseline** -- sha256 of every protected file, committed as
  ``.secure-check/baseline.json``. ``verify`` reports any drift. An agent that
  edits a risk limit and forgets the baseline is caught; one that regenerates
  the baseline leaves a diff on the baseline file itself, which is also
  protected, so the change is visible in review and in CI.
* **Append-only** -- files like a scoreboard or spend ledger may only grow.
  Any removed line in a push range is a violation.

This is evidence, not a lock: the lock is a branch ruleset on GitHub.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .findings import Finding
from .policy import Policy
from .util import path_matches, run_git


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def protected_at(root: Path, policy: Policy, rev: str | None) -> list[str]:
    if rev:
        out = run_git(["ls-tree", "-r", "--name-only", "-z", rev], cwd=root, text=False)
        names = [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]
    else:
        out = run_git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root, text=False)
        names = [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]
    pats = list(policy.protected_paths) + [policy.baseline_path.rsplit("/", 1)[0] + "/**",
                                           ".secure-check.toml"]
    return sorted(n for n in names if path_matches(n, pats) and n != policy.baseline_path)


def _content(root: Path, rev: str | None, path: str) -> bytes | None:
    if rev:
        try:
            return run_git(["show", f"{rev}:{path}"], cwd=root, text=False)
        except RuntimeError:
            return None
    try:
        return (root / path).read_bytes()
    except OSError:
        return None


def snapshot(root: Path, policy: Policy, rev: str | None = "HEAD") -> dict:
    files = {}
    for p in protected_at(root, policy, rev):
        data = _content(root, rev, p)
        if data is not None:
            files[p] = _sha(data)
    commit = run_git(["rev-parse", "HEAD"], cwd=root).strip() if rev else None
    return {"version": 1, "commit": commit, "protected_paths": list(policy.protected_paths), "files": files}


def baseline_digest(baseline: dict) -> str:
    canon = json.dumps(baseline.get("files", {}), sort_keys=True, separators=(",", ":")).encode()
    return _sha(canon)[:16]


def write_baseline(root: Path, policy: Policy, rev: str | None = "HEAD") -> tuple[Path, str]:
    snap = snapshot(root, policy, rev)
    target = policy.baseline_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target, baseline_digest(snap)


def load_baseline(policy: Policy) -> dict | None:
    f = policy.baseline_file
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except ValueError:
        return {"corrupt": True}


def verify(root: Path, policy: Policy, rev: str | None = None) -> list[Finding]:
    """Compare protected files (working tree by default) with the baseline."""
    if not policy.protected_paths:
        return []
    base = load_baseline(policy)
    if base is None:
        return [Finding("integrity_no_baseline", "medium", policy.baseline_path,
                        "Protected paths are configured but no baseline exists",
                        fix="Run `secure-check baseline` and commit the file it writes.")]
    if base.get("corrupt"):
        return [Finding("integrity_baseline_corrupt", "high", policy.baseline_path,
                        "Baseline file is not valid JSON", fix="Regenerate it with `secure-check baseline`.")]
    now = snapshot(root, policy, rev)["files"]
    then = base.get("files", {})
    out: list[Finding] = []
    for p in sorted(set(now) | set(then)):
        if p in now and p not in then:
            out.append(Finding("integrity_new_protected", "medium", p,
                               "New file under a protected path is not in the baseline",
                               fix="If the owner approved it, re-run `secure-check baseline` and commit."))
        elif p in then and p not in now:
            out.append(Finding("integrity_removed", "high", p, "Protected file removed",
                               fix="Restore it, or if the owner approved the removal, re-baseline."))
        elif now[p] != then[p]:
            out.append(Finding("integrity_changed", "high", p,
                               "Protected file differs from the owner's baseline",
                               fix="Stop. If the owner approved this exact change, re-run "
                                   "`secure-check baseline` and commit both files together; otherwise revert."))
    return out


APPROVED_MARK = "[owner-approved]"


def all_commits_marked(root: Path, rev_args: list[str] | str) -> bool:
    """True when every commit in the range carries the owner's approval marker in its subject."""
    args = [rev_args] if isinstance(rev_args, str) else list(rev_args)
    try:
        # merge commits carry no change of their own (GitHub's merge button cannot add the
        # marker); the commits they bring in are what must be marked.
        subjects = run_git(["log", "--no-merges", "--format=%s", *args], cwd=root)
    except RuntimeError:
        return False
    lines = [s for s in subjects.splitlines() if s.strip()]
    return bool(lines) and all(APPROVED_MARK in s for s in lines)


def apply_owner_approval(findings: list[Finding], root: Path, rev_args: list[str] | str, owner_env: bool) -> list[Finding]:
    """Drop protected_path_changed when the owner approved (env var, or every commit marked).
    Tamper rules (append-only, immutable) are never waived by the marker."""
    if owner_env:
        return [f for f in findings if f.rule != "protected_path_changed"]
    if all_commits_marked(root, rev_args):
        return [f for f in findings if f.rule != "protected_path_changed"]
    return findings


def range_checks(root: Path, policy: Policy, rev_range: str) -> list[Finding]:
    """For a push/PR range: protected paths touched, append-only files shrunk."""
    out: list[Finding] = []
    try:
        names_raw = run_git(["diff", "--name-status", "-z", rev_range], cwd=root, text=False)
    except RuntimeError as exc:
        return [Finding("integrity_range_error", "low", rev_range, f"Could not diff range: {exc}")]
    parts = [p.decode("utf-8", "surrogateescape") for p in names_raw.split(b"\0") if p]
    changes: list[tuple[str, str]] = []
    i = 0
    while i < len(parts):
        status = parts[i]
        if status.startswith(("R", "C")):
            changes.append((status[0], parts[i + 2]))
            i += 3
        else:
            changes.append((status[0], parts[i + 1]))
            i += 2

    if policy.protected_paths:
        for status, name in changes:
            if path_matches(name, policy.protected_paths):
                out.append(Finding("protected_path_changed", "high", name,
                                   f"Protected file {'deleted' if status == 'D' else 'changed'} in {rev_range}",
                                   fix="Protected files change only with the owner's explicit approval. "
                                       "If approved: re-baseline and say so in the commit message. Otherwise revert.",
                                   tags=["protected"]))
    if policy.immutable_paths:
        for status, name in changes:
            if status in ("M", "D") and path_matches(name, policy.immutable_paths):
                out.append(Finding("immutable_modified", "critical", name,
                                   f"Archived file {'deleted' if status == 'D' else 'modified'} in {rev_range}",
                                   fix="Archives are written once. Restore the previous content; investigate.",
                                   tags=["tamper"]))
    if policy.append_only_paths:
        for status, name in changes:
            if not path_matches(name, policy.append_only_paths):
                continue
            if status == "D":
                out.append(Finding("append_only_deleted", "critical", name, "Append-only file deleted",
                                   fix="Restore the file from the previous commit."))
                continue
            stat = run_git(["diff", "--numstat", rev_range, "--", name], cwd=root).strip()
            if not stat:
                continue
            added, deleted, _ = stat.split("\t", 2)
            if deleted not in ("0", "-"):
                out.append(Finding("append_only_violation", "critical", name,
                                   f"{deleted} line(s) removed from an append-only file (+{added}/-{deleted})",
                                   fix="Append-only files (scoreboards, ledgers, spend logs) never lose lines. "
                                       "Restore the removed lines; investigate who changed history.",
                                   tags=["tamper"]))
    return out
