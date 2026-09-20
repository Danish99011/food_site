"""Claude Code PreToolUse / SessionStart hook.

Reads the hook JSON on stdin, decides, writes a decision JSON on stdout.
Exit code is always 0 for a decision; the decision itself carries deny/ask.
For git commit/push/add the guard fails CLOSED: an internal error is a deny.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from . import files as filecheck
from . import gitscan, integrity, report
from .findings import Finding, at_or_above, dedupe
from .policy import Policy, load
from .secrets import Scanner
from .util import _git_env, repo_root, run_git

OWNER_ENV = "SECURE_CHECK_OWNER"
APPROVED_MARK = integrity.APPROVED_MARK

READERS = {"cat", "less", "more", "head", "tail", "bat", "strings", "xxd", "hexdump", "od", "tac",
           "nl", "base64", "base32", "grep", "egrep", "fgrep", "rg", "ag", "awk", "gawk", "sed", "cut",
           "sort", "uniq", "jq", "yq", "python", "python3", "python2", "ruby", "perl", "node",
           "cp", "tee", "paste", "view", "vim", "vi", "nano", "emacs", "dd", "pv", "fold", "expand",
           "unexpand", "column", "tr", "rev", "shuf", "install", "split", "csplit", "pr", "fmt",
           "comm", "join", "xxd", "uuencode", "cmp", "diff"}
UPLOADERS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "rsync", "sftp", "ftp", "telnet", "socat", "gh", "aws", "gsutil", "gcloud"}
SECRET_VAR = re.compile(r"\$\{?[A-Za-z_]*(?:KEY|SECRET|TOKEN|PASS|PASSWORD|CREDENTIAL)[A-Za-z_]*\b", re.I)
SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\n|\|)\s*")
_CRED_URL = re.compile(r"://[^/:@\s]+:[^@\s]+@")


# ---- decisions ---------------------------------------------------------------
def _emit(decision: str, reason: str, event: str = "PreToolUse") -> int:
    out = {"hookSpecificOutput": {"hookEventName": event, "permissionDecision": decision,
                                  "permissionDecisionReason": reason}}
    sys.stdout.write(json.dumps(out))
    return 0


def _deny(reason: str) -> int:
    return _emit("deny", "secure-check BLOCKED this. Do not work around it (no --no-verify, no allow-list "
                         "edits, no renaming/encoding the file). " + reason)


def _ask(reason: str) -> int:
    return _emit("ask", "secure-check: owner approval required. " + reason)


def _owner_present() -> bool:
    return os.environ.get(OWNER_ENV) == "1"


def _report(findings: list[Finding], limit: int = 2500) -> str:
    text = report.text(findings, color=False)
    return text if len(text) <= limit else text[:limit] + "\n  ... (truncated)"


# ---- entry -------------------------------------------------------------------
def main(stdin_text: str | None = None) -> int:
    raw = stdin_text if stdin_text is not None else sys.stdin.read()
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        return 0
    event = data.get("hook_event_name", "PreToolUse")
    cwd = data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    root = repo_root(cwd) or Path(cwd)
    try:
        policy = load(root)
    except RuntimeError as exc:
        return _deny(f"policy file is broken: {exc}")

    if event == "SessionStart":
        return session_start(root, policy)
    if event != "PreToolUse":
        return 0
    tool = data.get("tool_name", "")
    tin = data.get("tool_input", {}) or {}
    try:
        if tool == "Bash":
            return bash(tin.get("command", "") or "", root, policy)
        if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            return write(tool, tin, root, policy)
    except Exception as exc:  # fail closed only for the dangerous verbs
        cmd = tin.get("command", "") if tool == "Bash" else tool
        dangerous = tool != "Bash"
        if tool == "Bash":
            try:
                segs = _expand_segments(cmd)
                dangerous = any(_is_git(t, v) for t in segs for v in ("commit", "push", "add"))
            except Exception:
                dangerous = True
            if not dangerous and _GIT_VERB_RAW.search(_strip_heredocs(cmd)):
                dangerous = True  # a git verb we could not attribute -> fail closed
        if dangerous:
            return _deny(f"the guard hit an internal error and fails closed: {type(exc).__name__}: {exc}")
        return 0
    return 0


# ---- Bash --------------------------------------------------------------------
HEREDOC_START = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
CONTROL_TOKENS = {"|", "||", "&&", ";", ";;", "&", "(", ")", "{", "}"}
WRAPPERS = ("sudo", "time", "nice", "ionice", "chrt", "nohup", "setsid", "setarch", "command",
            "builtin", "exec", "timeout", "stdbuf", "doas", "eatmydata", "proxychains",
            "proxychains4", "catchsegv")
RUNNERS = ("env", "xargs")  # a wrapper ONLY when a real command follows (bare `env` is a dump)
SHELLS = ("sh", "bash", "zsh", "dash", "ash", "ksh", "busybox")
# the verb must stand alone: `--no-commit`, `--commit-graph`, `add-on` are flags/words, not verbs
_GIT_VERB_RAW = re.compile(r"(?:^|[\s/])git\b[^\n;|&]*?(?<![-\w])(commit|push|add)(?![-\w])")


def _strip_heredocs(command: str) -> str:
    """Drop heredoc bodies: they are data fed to a program, not commands."""
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = HEREDOC_START.search(line)
        if m:
            term = m.group(2)
            i += 1
            while i < len(lines) and lines[i].strip() != term:
                i += 1
        i += 1
    return "\n".join(out)


def _segments(command: str) -> list[list[str]]:
    """Split a shell command line into simple commands, respecting quotes."""
    text = _strip_heredocs(command).replace("\r\n", "\n").replace("\n", " ; ")
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        tokens = list(lex)
    except ValueError:
        tokens = []
        for part in SEGMENT_SPLIT.split(text):
            tokens += part.split() + ["|"]
    segs: list[list[str]] = []
    cur: list[str] = []
    for t in tokens:
        if t in CONTROL_TOKENS:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    cleaned = []
    for toks in segs:
        while toks and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]) or toks[0] in WRAPPERS):
            toks = toks[2:] if toks[0] == "timeout" and len(toks) > 1 else toks[1:]
        toks = [t for t in toks if not re.match(r"^\d*[<>]+&?\d*$", t)]
        if toks:
            cleaned.append(toks)
    return cleaned


def _prog(tok: str) -> str:
    return tok.rsplit("/", 1)[-1]


def _is_git(toks: list[str], verb: str) -> bool:
    if not toks or _prog(toks[0]) != "git":
        return False
    i = 1
    while i < len(toks) and (toks[i].startswith("-") or toks[i] in ("--no-pager",)):
        if toks[i] in ("-C", "-c", "--git-dir", "--work-tree") and i + 1 < len(toks):
            i += 1
        i += 1
    return i < len(toks) and toks[i] == verb


def _operand(arg: str) -> str:
    """Strip dd-style if=/of= and @ prefixes so the filename is seen."""
    for pre in ("if=", "of=", "file=", "@"):
        if arg.startswith(pre):
            return arg[len(pre):]
    return arg


def _danger_name(arg: str) -> bool:
    base = arg.rsplit("/", 1)[-1]
    hit = filecheck._basename_hits(base)
    return bool(hit and hit[0] in ("critical", "high"))


def _unwrap_runner(toks: list[str]) -> list[str] | None:
    """For `env`/`xargs`, return the inner command they run, or None if there is
    no inner command (bare `env` / `env -i` is a dump, not a wrapper)."""
    prog = _prog(toks[0])
    i = 1
    if prog == "env":
        while i < len(toks):
            a = toks[i]
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a):
                i += 1
            elif a in ("-u", "--unset", "-C", "--chdir", "-S", "--split-string"):
                i += 2
            elif a.startswith("-"):
                i += 1
            else:
                break
    elif prog == "xargs":
        while i < len(toks) and toks[i].startswith("-"):
            i += 2 if toks[i] in ("-I", "-n", "-P", "-a", "-E", "-d", "-s", "-L", "-i") else 1
    else:
        return toks
    rest = toks[i:]
    return rest if rest else None


def _expand_segments(command: str, _depth: int = 0) -> list[list[str]]:
    """Segments of a command, recursing into `sh -c "..."` and `eval ...`."""
    segs = _segments(command)
    if _depth > 4:
        return segs
    out: list[list[str]] = []
    for toks in segs:
        prog = _prog(toks[0]) if toks else ""
        if prog in RUNNERS:
            inner = _unwrap_runner(toks)
            if inner is not None:
                out += _expand_segments(" ".join(inner), _depth + 1) if _prog(inner[0]) in SHELLS or _prog(inner[0]) in RUNNERS else [inner]
                continue
            # bare env/xargs: leave as-is so _check_segment can judge it
        if prog in SHELLS and "-c" in toks:
            i = toks.index("-c")
            if i + 1 < len(toks):
                out += _expand_segments(toks[i + 1], _depth + 1)
                continue
        if prog == "eval" and len(toks) > 1:
            out += _expand_segments(" ".join(toks[1:]), _depth + 1)
            continue
        out.append(toks)
    return out


def _git_target(toks: list[str], cwd: Path) -> Path:
    """The directory a git command acts on: `git -C dir` wins, else the effective cwd."""
    i = 1
    target = cwd
    while i < len(toks) and toks[i].startswith("-"):
        if toks[i] == "-C" and i + 1 < len(toks):
            target = (target / toks[i + 1]).resolve() if not toks[i + 1].startswith("/") else Path(toks[i + 1])
            i += 2
            continue
        if toks[i] in ("-c", "--git-dir", "--work-tree") and i + 1 < len(toks):
            i += 2
            continue
        i += 1
    return target


def _with_cwd(segs: list[list[str]], start: Path) -> list[tuple[list[str], Path]]:
    """Pair each segment with the working directory in effect (tracks `cd`/`pushd`)."""
    out = []
    cwd = start
    for toks in segs:
        if toks and toks[0] in ("cd", "pushd"):
            if len(toks) > 1 and not toks[1].startswith("-"):
                arg = os.path.expanduser(toks[1])
                cwd = Path(arg) if arg.startswith("/") else (cwd / arg)
            else:
                cwd = Path(os.path.expanduser("~"))
            continue
        out.append((toks, cwd))
    return out


def _repo_for(toks: list[str], cwd: Path, root: Path, policy: Policy) -> tuple[Path, Policy]:
    target = _git_target(toks, cwd)
    r = repo_root(target)
    if r is None or r.resolve() == root.resolve():
        return root, policy
    try:
        return r, load(r)
    except RuntimeError:
        return r, Policy(root=r)


def bash(command: str, root: Path, policy: Policy) -> int:
    segs = _expand_segments(command)
    for toks in segs:
        d = _check_segment(toks, command, root, policy)
        if d is not None:
            return d
    located = _with_cwd(segs, root)
    for toks, cwd in located:
        if _is_git(toks, "add"):
            r, pol = _repo_for(toks, cwd, root, policy)
            d = _check_add(toks, r, pol)
            if d is not None:
                return d
    for toks, cwd in located:
        if _is_git(toks, "commit"):
            r, pol = _repo_for(toks, cwd, root, policy)
            d = _check_commit(toks, segs, r, pol)
            if d is not None:
                return d
    for toks, cwd in located:
        if _is_git(toks, "push"):
            r, pol = _repo_for(toks, cwd, root, policy)
            d = _check_push(toks, r, pol)
            if d is not None:
                return d
    # Backstop: a git commit/push/add is present in the command text (heredoc bodies,
    # which are data, excluded) but no segment was attributed to it (an unwrap the parser
    # missed). Fail closed rather than allow.
    if _GIT_VERB_RAW.search(_strip_heredocs(command)) and not any(
            _is_git(t, v) for t in segs for v in ("commit", "push", "add")):
        return _deny("a `git commit`/`push`/`add` is present but the guard could not parse how it "
                     "is invoked, so it fails closed. Run git plainly (no wrapper/eval) so it can be scanned.")
    return 0


def _check_segment(toks: list[str], command: str, root: Path, policy: Policy) -> int | None:
    prog = _prog(toks[0])
    args = toks[1:]
    # history rewrites and force pushes: owner only
    if prog == "git":
        if (_is_git(toks, "commit") or _is_git(toks, "push")) and any(
                a in ("--no-verify", "-n") or (a.startswith("-") and not a.startswith("--") and "n" in a and _is_git(toks, "commit"))
                for a in args):
            return _deny("--no-verify / commit -n skips the git hooks that scan for secrets. Not allowed; "
                         "fix what the scan reports instead of bypassing it.")
        if _is_git(toks, "push") and policy.block_force_push:
            if any(a in ("--force", "-f", "--force-with-lease", "--mirror") or a.startswith("--force") or
                   (a.startswith("+") and ":" in a) for a in args):
                if not _owner_present():
                    return _deny("force-push / mirror rewrites shared history. Owner-only. "
                                 "Ask the owner; they can run it with SECURE_CHECK_OWNER=1.")
            for a in args:
                target = a.split(":", 1)[1] if ":" in a else a
                if target in policy.block_direct_push_to and not _owner_present():
                    return _deny(f"direct push to '{target}' is blocked by policy; open a pull request.")
        if any(_is_git(toks, v) for v in ("filter-branch", "filter-repo", "replace")) and not _owner_present():
            return _deny("history rewrite is owner-only (see docs/INCIDENT-RUNBOOK.md for the purge procedure).")
        if _is_git(toks, "config") and "credential.helper" in args and "store" in args:
            return _deny("storing credentials in plaintext with credential.helper=store is not allowed.")
        if (_is_git(toks, "remote") or _is_git(toks, "clone")) and any(_CRED_URL.search(a) for a in args):
            return _deny("a remote URL with an embedded credential leaks it into .git/config and every log.")
    # reading a credential file into the transcript
    if prog in READERS and any(_danger_name(_operand(a)) for a in args if not a.startswith("-")):
        return _deny("that reads a credential file; the value would land in the transcript. "
                     "Use `python3 -m secure_check keys <file>` to see key names and lengths only.")
    if prog in ("printenv", "export") and (not args or args == ["-p"] or any(SECRET_VAR.search("$" + a) for a in args)):
        return _deny("dumping environment variables prints API keys. Check a single one with "
                     "`[ -n \"$NAME\" ] && echo set || echo unset`.")
    if prog == "env" and _unwrap_runner(toks) is None:
        return _deny("`env` prints every API key in the environment. Use `[ -n \"$NAME\" ] && echo set`.")
    if prog == "set" and not args:
        return _deny("bare `set` prints every variable including keys.")
    if prog == "echo" and any(SECRET_VAR.search(a) for a in args):
        return _deny("echoing a secret variable prints it. Use `[ -n \"$NAME\" ] && echo set || echo unset`.")
    # sending a credential file somewhere
    if prog in UPLOADERS and any(_danger_name(a.lstrip("@").split("=", 1)[-1].lstrip("@")) for a in args):
        return _deny("that would send a credential file over the network.")
    if prog == "rm" and any(a.rstrip("/") in (".git", ".secure-check", ".secure-check/baseline.json") for a in args):
        return _deny("deleting the repository metadata or the guard is owner-only.")
    return None


def _scan_paths(paths: list[str], root: Path, policy: Policy) -> list[Finding]:
    sc = Scanner(policy)
    out: list[Finding] = []
    for p in paths:
        rel = p.replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        full = root / rel
        content = None
        if full.is_file():
            try:
                content = full.read_bytes()
            except OSError:
                content = None
        out += filecheck.check_path(rel, policy, content)
        if content is not None:
            out += sc.scan_bytes(content, rel)
    return dedupe(out)


def _worktree_candidates(root: Path, include_untracked: bool) -> list[str]:
    out = run_git(["status", "--porcelain", "-z", "--untracked-files=all"], cwd=root, text=False)
    paths = []
    for entry in out.split(b"\0"):
        if len(entry) < 4:
            continue
        code, name = entry[:2], entry[3:].decode("utf-8", "surrogateescape")
        if code == b"??" and not include_untracked:
            continue
        if b"D" in code:
            continue
        paths.append(name)
    return paths


def _resolve_pathspecs(root: Path, pathspecs: list[str]) -> list[str]:
    """What `git add <pathspecs>` would actually stage: tracked, modified and
    untracked (not ignored) files matching, resolved by git itself."""
    try:
        out = run_git(["ls-files", "-z", "--cached", "--modified", "--others",
                       "--exclude-standard", "--", *pathspecs], cwd=root, text=False)
        paths = [q.decode("utf-8", "surrogateescape") for q in out.split(b"\x00") if q]
        if paths:
            return sorted(set(paths))
    except (RuntimeError, TypeError):
        pass
    expanded: list[str] = []
    for p in pathspecs:
        lit = p.split(":", 2)[-1] if p.startswith(":") else p
        full = root / lit
        if full.is_dir():
            expanded += [str(x.relative_to(root)) for x in full.rglob("*")
                         if x.is_file() and "/.git/" not in str(x)]
        else:
            expanded.append(lit)
    return expanded


def _check_add(toks: list[str], root: Path, policy: Policy) -> int | None:
    rest = toks[1:]
    i = 0
    while i < len(rest) and rest[i] != "add":
        i += 1 + (1 if rest[i] in ("-C", "-c", "--git-dir", "--work-tree") else 0)
    args = [a for a in rest[i + 1:] if a != "--"]
    flags = [a for a in args if a.startswith("-")]
    pathspecs = [a for a in args if not a.startswith("-")]
    if any(f in ("-A", "--all", "-u", "--update") for f in flags) or not pathspecs:
        paths = _worktree_candidates(root, include_untracked=not any(f in ("-u", "--update") for f in flags))
    else:
        paths = _resolve_pathspecs(root, pathspecs)
    findings = at_or_above(_scan_paths(paths, root, policy), policy.fail_on)
    if findings:
        return _deny("`git add` would stage a credential.\n" + _report(findings) +
                     "\nFix: leave the file out of the commit, make sure .gitignore covers it "
                     "(and its .bak/.old copies), and tell the owner if it was ever pushed.")
    return None


def _check_commit(toks: list[str], segs: list[list[str]], root: Path, policy: Policy) -> int | None:
    findings: list[Finding] = []
    sc = Scanner(policy)
    for path, blob in gitscan.staged_changes(root):
        findings += filecheck.check_path(path, policy, blob)
        findings += sc.scan_bytes(blob, path)
    # `git commit -a` adds modified tracked files at commit time
    if any(a in ("-a", "--all") or (a.startswith("-") and not a.startswith("--") and "a" in a) for a in toks[2:]):
        findings += _scan_paths(_worktree_candidates(root, include_untracked=False), root, policy)
    findings = dedupe(findings)
    bad = at_or_above(findings, policy.fail_on)
    if bad:
        return _deny("the commit contains a credential or a credential-named file.\n" + _report(bad) +
                     "\nFix: `git rm --cached <path>` (keeps the file on disk), add an ignore rule that also "
                     "covers backup copies, then commit again. If the value was ever pushed, the owner must "
                     "rotate it (link in the finding).")
    if policy.protected_paths and not _owner_present():
        staged = [p for p, _ in gitscan.staged_changes(root)]
        try:
            deleted = run_git(["diff", "--cached", "--name-only", "--diff-filter=D"], cwd=root).split()
        except RuntimeError:
            deleted = []
        touched = [p for p in staged + deleted if _protected(p, policy)]
        msg = " ".join(toks)
        if touched and APPROVED_MARK not in msg:
            return _ask(f"this commit changes protected file(s): {', '.join(touched[:8])}. These change only "
                        f"with the owner's explicit approval. If approved: run `python3 -m secure_check baseline`, "
                        f"stage the baseline too, and put {APPROVED_MARK} in the commit subject.")
    return None


def _protected(path: str, policy: Policy) -> bool:
    from .util import path_matches
    return path_matches(path, policy.protected_paths)


ALL_LOCAL = (["--branches", "--tags", "--not", "--remotes"], None)


def _push_range(toks: list[str], root: Path) -> tuple[list[str], str | None]:
    """(git-log revision args, A..B range for diff checks or None).

    --all/--tags/--mirror or several refspecs -> scan every local commit not yet on
    any remote, so a secret on another branch cannot ride out unscanned."""
    # locate the push verb, skipping git's own leading options
    rest = toks[1:]
    i = 0
    while i < len(rest) and rest[i] != "push":
        i += 1 + (1 if rest[i] in ("-C", "-c", "--git-dir", "--work-tree") else 0)
    after = rest[i + 1:]
    flags = [a for a in after if a.startswith("-")]
    positional = [a for a in after if not a.startswith("-")]
    if any(f in ("--all", "--tags", "--mirror", "--branches") for f in flags):
        return ALL_LOCAL
    remote = positional[0] if positional else "origin"
    refspecs = positional[1:]
    if len(refspecs) > 1:
        return ALL_LOCAL
    refspec = refspecs[0] if refspecs else None
    src, dst = "HEAD", None
    if refspec:
        if ":" in refspec:
            src, dst = refspec.split(":", 1)
        else:
            src = dst = refspec
        src = src.lstrip("+") or "HEAD"
    if dst is None:
        try:
            dst = run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=root).strip()
        except RuntimeError:
            dst = None
    if dst:
        dst = dst.replace("refs/heads/", "")
        base = f"{remote}/{dst}"
        proc = subprocess.run(["git", "rev-parse", "--verify", "-q", base], cwd=str(root),
                              capture_output=True, text=True, env=_git_env())
        if proc.returncode == 0:
            return [f"{base}..{src}"], f"{base}..{src}"
    return [src, "--not", "--remotes"], None


def _check_push(toks: list[str], root: Path, policy: Policy) -> int | None:
    rev_args, rng = _push_range(toks, root)
    sc = Scanner(policy)
    findings, _ = gitscan.scan_history(root, sc, policy, rev_range=rev_args, max_commits=policy.max_commits)
    if rng:
        findings += integrity.range_checks(root, policy, rng)
    findings = integrity.apply_owner_approval(dedupe(findings), root, rev_args, _owner_present())
    bad = at_or_above(findings, policy.fail_on)
    if bad:
        return _deny("these commits must not leave this machine.\n" + _report(bad) +
                     "\nIf a real credential is in history: the owner rotates it first, then purges "
                     "(docs/INCIDENT-RUNBOOK.md). Protected-file changes need the owner's approval and "
                     f"{APPROVED_MARK} in the commit subject.")
    return None


# ---- Write / Edit ------------------------------------------------------------
def write(tool: str, tin: dict, root: Path, policy: Policy) -> int:
    path = tin.get("file_path") or tin.get("notebook_path") or ""
    if not path:
        return 0
    try:
        rel = str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        rel = path
    if _danger_name(rel) and not rel.endswith((".example", ".sample", ".template")):
        return _deny(f"writing a credential-named file ({rel}) through the editor puts its content in the "
                     "transcript. Credentials are created by the login flow and stay out of git.")
    parts = [tin.get("content"), tin.get("new_string"), tin.get("new_source"), tin.get("source")]
    if isinstance(tin.get("edits"), list):
        parts += [e.get("new_string") for e in tin["edits"] if isinstance(e, dict)]
    if isinstance(tin.get("cells"), list):
        parts += [c.get("source") for c in tin["cells"] if isinstance(c, dict)]
    content = "\n".join(str(x) for x in parts if x)
    if content:
        sc = Scanner(policy)
        bad = at_or_above(dedupe(sc.scan_text(str(content), rel)), policy.fail_on)
        if bad:
            return _deny("the text being written contains a credential.\n" + _report(bad) +
                         "\nLoad it from the environment or a gitignored file instead.")
    if policy.protected_paths and _protected(rel, policy) and not _owner_present():
        return _ask(f"'{rel}' is a protected file (owner-only changes). Approve only if you asked for this "
                    f"exact change; afterwards the agent must re-run `secure_check baseline` and commit both.")
    return 0


# ---- SessionStart --------------------------------------------------------------
def session_start(root: Path, policy: Policy) -> int:
    from . import installer
    notes = []
    try:
        installed = installer.install_git_hooks(root, quiet=True)
        notes.append("git hooks " + ("installed" if installed else "already present"))
    except Exception as exc:
        notes.append(f"git hooks NOT installed ({exc})")
    context = (
        "secure-check is active in this repository. Rules that apply to every agent: never commit, print, "
        "echo or upload a credential (.env, token*.json, keys, client secrets, service accounts, or backup "
        "copies of them); never bypass a guard (no --no-verify, no allow-list edits); protected files listed "
        "in .secure-check.toml change only with the owner's explicit approval and a re-baseline; "
        "append-only ledgers never lose lines; force-push and history rewrites are owner-only. "
        "Run `PYTHONPATH=.secure-check/lib python3 -m secure_check scan --staged` before committing; "
        "the security-guard agent gives the final PASS/BLOCK. Status: " + "; ".join(notes) + "."
    )
    sys.stdout.write(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                                         "additionalContext": context}}))
    return 0
