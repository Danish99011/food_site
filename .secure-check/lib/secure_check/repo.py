"""Repository hygiene that is not about file contents."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .findings import Finding
from .policy import Policy
from .util import _git_env, fingerprint, redact, run_git

_CRED_URL = re.compile(r"^(https?://)([^/:@\s]+):([^@\s]+)@(.*)$")


def remotes(root: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        text = run_git(["remote", "-v"], cwd=root)
    except RuntimeError:
        return out
    seen = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, url = parts[0], parts[1]
        m = _CRED_URL.match(url)
        if m and (name, m.group(3)) not in seen:
            seen.add((name, m.group(3)))
            out.append(Finding("remote_url_credential", "critical", f".git/config (remote {name})",
                               "Remote URL embeds a credential; it will leak into logs, error output and clones",
                               fingerprint=fingerprint(m.group(3)), preview=redact(m.group(3)),
                               fix=f"git remote set-url {name} {m.group(1)}{m.group(4)} ; revoke that token; "
                                   "use a credential helper or the platform's built-in auth."))
    return out


def tracked_but_ignored(root: Path) -> list[Finding]:
    try:
        out = run_git(["ls-files", "-ci", "--exclude-standard", "-z"], cwd=root, text=False)
    except RuntimeError:
        return []
    names = [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]
    return [Finding("tracked_despite_gitignore", "high", n,
                    "File is tracked even though .gitignore now excludes it (committed before the rule)",
                    fix="git rm --cached <file> && git commit ; rotate it if it is a credential; purge history.")
            for n in names]


def gitignore_canaries(root: Path, policy: Policy) -> list[Finding]:
    """Which of the must-be-ignored paths would git happily add right now?"""
    if not policy.canaries:
        return []
    proc = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"], cwd=str(root),
                          input="\n".join(policy.canaries) + "\n", capture_output=True, text=True, env=_git_env())
    ignored = set(proc.stdout.splitlines())
    missing = [c for c in policy.canaries if c not in ignored]
    if not missing:
        return []
    return [Finding("gitignore_gap", "medium", ".gitignore",
                    f"{len(missing)} credential/data path(s) are NOT ignored: " + ", ".join(missing[:12]) +
                    (" ..." if len(missing) > 12 else ""),
                    fix="Run `secure-check init` to append the standard ignore block, then `git add .gitignore`.")]


def large_tracked(root: Path, limit_mb: int = 50) -> list[Finding]:
    try:
        out = run_git(["ls-files", "-z"], cwd=root, text=False)
    except RuntimeError:
        return []
    res = []
    for raw in out.split(b"\0"):
        if not raw:
            continue
        p = raw.decode("utf-8", "surrogateescape")
        try:
            size = (root / p).stat().st_size
        except OSError:
            continue
        if size > limit_mb * 1024 * 1024:
            res.append(Finding("large_tracked_file", "low", p, f"{size // (1024 * 1024)} MB tracked in git",
                               fix="GitHub rejects >100 MB; keep media in object storage, not git."))
    return res


def committers(root: Path, n: int = 500) -> list[Finding]:
    """Who has written to this history. Informational: an unknown name is a question."""
    try:
        out = run_git(["log", f"-n{n}", "--format=%an <%ae>"], cwd=root)
    except RuntimeError:
        return []
    counts: dict[str, int] = {}
    for line in out.splitlines():
        counts[line] = counts.get(line, 0) + 1
    who = ", ".join(f"{k} x{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
    return [Finding("committers", "info", "git log", f"Identities in the last {n} commits: {who}",
                    fix="If a name here is not you or your agent sessions, treat it as an incident.")]


def hooks_installed(root: Path, policy: Policy) -> list[Finding]:
    if not policy.require_git_hooks:
        return []
    try:
        hooks_path = run_git(["config", "--get", "core.hooksPath"], cwd=root, check=False).strip()
    except RuntimeError:
        hooks_path = ""
    hook_dir = (root / hooks_path) if hooks_path else (root / ".git" / "hooks")
    missing = []
    for name in ("pre-commit", "pre-push"):
        h = hook_dir / name
        try:
            if not h.exists() or "secure-check" not in h.read_text(encoding="utf-8", errors="replace"):
                missing.append(name)
        except OSError:
            missing.append(name)
    if not missing:
        return []
    return [Finding("git_hooks_missing", "low", str(hook_dir),
                    f"secure-check git hooks not installed here: {', '.join(missing)}",
                    fix="Run `secure-check install-hooks` (the SessionStart hook does this automatically in Claude Code).")]
