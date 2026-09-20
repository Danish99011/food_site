"""Git-aware scanning: tracked files, the index (staged), a push range, history."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from . import files as filecheck
from .findings import Finding
from .policy import Policy
from .secrets import Scanner
from .util import _git_env, run_git

_COMMIT = re.compile(rb"^\x00commit (?P<sha>[0-9a-f]{40}) (?P<short>[0-9a-f]{7,}) (?P<date>\S+) (?P<author>.*)$")
_DIFF = re.compile(rb"^diff --git a/(?P<a>.*) b/(?P<b>.*)$")
_HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")


def tracked_files(root: Path) -> list[str]:
    out = run_git(["ls-files", "-z"], cwd=root, text=False)
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def staged_changes(root: Path) -> list[tuple[str, bytes]]:
    """(path, content-as-staged) for every added/modified file in the index."""
    out = run_git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], cwd=root, text=False)
    result = []
    for raw in out.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        try:
            blob = run_git(["show", f":{path}"], cwd=root, text=False)
        except RuntimeError:
            continue
        result.append((path, blob))
    return result


def changed_in_range(root: Path, rev_range: str) -> list[str]:
    out = run_git(["diff", "--name-only", "-z", "--diff-filter=ACMR", rev_range], cwd=root, text=False)
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def blob_at(root: Path, rev: str, path: str) -> bytes | None:
    try:
        return run_git(["show", f"{rev}:{path}"], cwd=root, text=False)
    except RuntimeError:
        return None


def exists_at_head(root: Path, path: str) -> bool:
    proc = subprocess.run(["git", "cat-file", "-e", f"HEAD:{path}"], cwd=str(root),
                          capture_output=True, env=_git_env())
    return proc.returncode == 0


def scan_history(root: Path, scanner: Scanner, policy: Policy, *, rev_range: str | list[str] | None = None,
                 all_refs: bool = False, max_commits: int | None = None) -> tuple[list[Finding], int]:
    """Scan every ADDED line and every ADDED file name in the selected commits.

    Returns (findings, commits_scanned). Findings carry the short commit sha.
    Streaming: ``git log -p`` is read line by line, so a big repository does
    not have to fit in memory.
    """
    args = ["git", "--no-pager", "log", "-p", "--no-color", "--no-renames", "--unified=0",
            "--ignore-submodules", "--date=short", "--format=%x00commit %H %h %ad %an"]
    n = max_commits if max_commits is not None else policy.max_commits
    if n:
        args += ["-n", str(n)]
    if all_refs:
        args.append("--all")
    if rev_range:
        args += [rev_range] if isinstance(rev_range, str) else list(rev_range)
    args += ["--", "."]

    findings: list[Finding] = []
    commits = 0
    if subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=str(root), capture_output=True,
                      env=_git_env()).returncode != 0:
        return findings, 0  # no commits yet: nothing to scan
    short = None
    path = None
    new_line = 0
    seen_new_files: set[tuple[str, str]] = set()

    proc = subprocess.Popen(args, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_git_env())
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.rstrip(b"\r\n")
        m = _COMMIT.match(line)
        if m:
            commits += 1
            short = m.group("short").decode()
            path = None
            continue
        m = _DIFF.match(line)
        if m:
            path = m.group("b").decode("utf-8", "surrogateescape").strip('"')
            new_line = 0
            continue
        if line.startswith(b"new file mode") and path and short:
            key = (short, path)
            if key not in seen_new_files:
                seen_new_files.add(key)
                for f in filecheck.check_path(path, policy):
                    f.commit = short
                    f.message = f"Added in commit {short}: {f.message}"
                    findings.append(f)
            continue
        m = _HUNK.match(line)
        if m:
            new_line = int(m.group("start"))
            continue
        if line.startswith(b"+++") or line.startswith(b"---"):
            continue
        if line.startswith(b"+") and path:
            text = line[1:].decode("utf-8", "replace")
            for f in scanner.scan_text(text, path, commit=short, line_offset=new_line - 1):
                findings.append(f)
            new_line += 1
        elif line.startswith(b" "):
            new_line += 1
    err_txt = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
    proc.stdout.close()
    if proc.stderr:
        proc.stderr.close()
    proc.wait()
    if proc.returncode not in (0, 141):
        raise RuntimeError(f"git log failed: {err_txt.strip()[:300]}")

    # Annotate whether the offending file is still in HEAD (revoke either way;
    # purge only matters if it is gone from HEAD but alive in history).
    cache: dict[str, bool] = {}
    for f in findings:
        if f.path not in cache:
            cache[f.path] = exists_at_head(root, f.path)
        f.tags.append("still-in-HEAD" if cache[f.path] else "removed-from-HEAD")
    return findings, commits
