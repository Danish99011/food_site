"""Small helpers shared by every check: entropy, redaction, git, globbing."""
from __future__ import annotations

import hashlib
import math
import re
import subprocess
from pathlib import Path

# Values that look like a secret but are obviously a stand-in. Matched
# case-insensitively as substrings, so keep them specific enough not to hide
# real keys (a real key never contains the word "example").
_PLACEHOLDER_WORDS = (
    "example", "placeholder", "your_", "your-", "yourkey", "changeme", "change_me",
    "change-me", "dummy", "redacted", "sample", "fake", "test_key", "testkey",
    "insert_", "replace_me", "replace-me", "<", ">", "${", "{{", "%(", "todo",
    "fixme", "not_set", "notset", "none", "null", "undefined", "xxxxxxxx", "********",
    "0000000000", "deadbeef", "secret", "password", "passwd",
)
_SEQUENTIAL = re.compile(r"abcdefgh|bcdefghi|0123456789|1234567890|123456789|qwertyui|asdfghjk", re.I)
_REPEATED = re.compile(r"(.)\1{5,}")


def shannon_entropy(value: str) -> float:
    """Bits per character. ~4.7 for uniform base64, ~3.3 for hex, <3 for prose."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    if any(w in v for w in _PLACEHOLDER_WORDS):
        return True
    if _SEQUENTIAL.search(v) or _REPEATED.search(v):
        return True
    if re.fullmatch(r"[x*#_.\-0]+", v):
        return True
    return False


def fingerprint(secret: str) -> str:
    """Stable identifier for a secret that reveals nothing about it.

    Used to allow-list a known fake without writing it into the policy file,
    and to correlate the same secret across files and commits.
    """
    return hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def redact(secret: str) -> str:
    """Show only enough to recognise the family (prefix) and the length."""
    if len(secret) <= 8:
        return "********"
    return f"{secret[:4]}…({len(secret)} chars)"


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def run_git(args: list[str], cwd: Path | str, *, check: bool = True, text: bool = True):
    """Run git without ever inheriting a pager or prompting for credentials."""
    proc = subprocess.run(
        ["git", "--no-pager", *args],
        cwd=str(cwd),
        capture_output=True,
        text=text,
        env={**_git_env()},
    )
    if check and proc.returncode != 0:
        err = proc.stderr if text else proc.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"git {' '.join(args)} failed: {err.strip()}")
    return proc.stdout


def _git_env() -> dict[str, str]:
    import os
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_PAGER"] = "cat"
    env.setdefault("LC_ALL", "C.UTF-8")
    return env


def repo_root(start: Path | str = ".") -> Path | None:
    try:
        out = run_git(["rev-parse", "--show-toplevel"], cwd=start)
    except (RuntimeError, FileNotFoundError):
        return None
    return Path(out.strip())


def git_default_branch(root: Path) -> str:
    """Best effort: origin/HEAD, else 'main' if it exists, else 'master'."""
    try:
        ref = run_git(["symbolic-ref", "-q", "refs/remotes/origin/HEAD"], cwd=root).strip()
        if ref:
            return ref.rsplit("/", 1)[-1]
    except RuntimeError:
        pass
    for name in ("main", "master"):
        try:
            run_git(["rev-parse", "--verify", "-q", f"refs/heads/{name}"], cwd=root)
            return name
        except RuntimeError:
            continue
    return "main"


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """gitignore-ish glob: ``**`` spans directories, ``*`` does not.

    A pattern without a slash matches the basename anywhere (like .gitignore).
    """
    anchored = "/" in pattern.rstrip("/")
    pat = pattern.lstrip("/")
    out = []
    i = 0
    while i < len(pat):
        ch = pat[i]
        if ch == "*":
            if pat[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pat[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    body = "".join(out)
    if pat.endswith("/"):
        body += ".*"
    if anchored:
        return re.compile(rf"^{body}$")
    return re.compile(rf"(?:^|.*/){body}$")


def path_matches(path: str, patterns: list[str]) -> bool:
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return any(glob_to_regex(g).match(p) for g in patterns)
