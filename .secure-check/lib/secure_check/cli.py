"""Command line. ``python3 -m secure_check --help``."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, agents, files as filecheck, gitscan, integrity, report, repo as repocheck
from .findings import Finding, at_or_above, dedupe, rank
from .policy import Policy, load
from .secrets import Scanner
from .util import repo_root

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _root(args) -> Path:
    start = Path(args.root) if getattr(args, "root", None) else Path.cwd()
    root = repo_root(start)
    if root is None:
        raise SystemExit(f"secure-check: {start} is not inside a git repository")
    return root


def _finish(findings: list[Finding], policy: Policy, args, *, meta: dict | None = None, title: str = "secure-check") -> int:
    findings = dedupe(findings)
    fail_on = getattr(args, "fail_on", None) or policy.fail_on
    bad = at_or_above(findings, fail_on)
    fmt = getattr(args, "format", "text")
    shown = findings if getattr(args, "show_all", True) else bad
    if getattr(args, "quiet_ok", False) and not bad:
        return EXIT_CLEAN
    print(report.render(shown, fmt, version=__version__, meta=meta, title=title))
    if bad and fmt == "text":
        print(f"\nsecure-check: FAIL ({len(bad)} finding(s) at or above '{fail_on}')", file=sys.stderr)
    return EXIT_FINDINGS if bad else EXIT_CLEAN


# ---- commands ------------------------------------------------------------------
def cmd_scan(args) -> int:
    root = _root(args)
    policy = load(root)
    sc = Scanner(policy)
    findings: list[Finding] = []
    meta = {"root": str(root)}
    if args.staged:
        for path, blob in gitscan.staged_changes(root):
            findings += filecheck.check_path(path, policy, blob)
            findings += sc.scan_bytes(blob, path)
        meta["mode"] = "staged"
    elif args.range:
        hist, n = gitscan.scan_history(root, sc, policy, rev_range=args.range, max_commits=policy.max_commits)
        findings += hist
        findings += integrity.range_checks(root, policy, args.range)
        # the same owner-approval rule the hooks apply: protected-path changes pass when every
        # (non-merge) commit in the range carries the marker; tamper rules are never waived
        findings = integrity.apply_owner_approval(dedupe(findings), root, args.range,
                                                  os.environ.get("SECURE_CHECK_OWNER") == "1")
        meta.update(mode="range", range=args.range, commits=n)
    elif args.paths:
        for p in args.paths:
            rel = os.path.relpath(Path(p).resolve(), root)
            full = root / rel
            if full.is_dir():
                for f in full.rglob("*"):
                    if f.is_file() and "/.git/" not in str(f):
                        r = str(f.relative_to(root))
                        findings += filecheck.check_path(r, policy, f.read_bytes())
                        findings += sc.scan_file(root, r)
            elif full.is_file():
                findings += filecheck.check_path(rel, policy, full.read_bytes())
                findings += sc.scan_file(root, rel)
        meta["mode"] = "paths"
    else:
        for rel in gitscan.tracked_files(root):
            full = root / rel
            if not full.is_file():
                continue
            try:
                data = full.read_bytes()
            except OSError:
                continue
            findings += filecheck.check_path(rel, policy, data)
            findings += sc.scan_bytes(data, rel)
        findings += repocheck.tracked_but_ignored(root)
        findings += repocheck.gitignore_canaries(root, policy)
        meta["mode"] = "tracked"
    return _finish(findings, policy, args, meta=meta)


def cmd_history(args) -> int:
    root = _root(args)
    policy = load(root)
    sc = Scanner(policy)
    findings, n = gitscan.scan_history(root, sc, policy, rev_range=args.range, all_refs=not args.range,
                                       max_commits=args.max_commits or policy.max_commits)
    return _finish(findings, policy, args, meta={"commits_scanned": n}, title=f"secure-check history ({n} commits)")


def cmd_audit(args) -> int:
    from . import audit as auditmod
    root = _root(args)
    policy = load(root)
    findings, n = auditmod.collect(root, policy, history=not args.no_history, max_commits=args.max_commits)
    return _finish(findings, policy, args, meta={"history_commits": n}, title="secure-check audit")


def cmd_fleet(args) -> int:
    from . import fleet
    return fleet.main(args)


def cmd_baseline(args) -> int:
    root = _root(args)
    policy = load(root)
    if not policy.protected_paths:
        print("secure-check: no protected_paths in .secure-check.toml; nothing to baseline")
        return EXIT_CLEAN
    path, digest = integrity.write_baseline(root, policy, rev="HEAD" if args.head else None)
    print(f"baseline written: {path.relative_to(root)}  digest {digest}")
    print("Keep the digest somewhere outside the repository (a note on your phone). "
          "`secure-check verify` prints the current digest; if they differ and you did not approve a change, investigate.")
    return EXIT_CLEAN


def cmd_verify(args) -> int:
    root = _root(args)
    policy = load(root)
    findings = integrity.verify(root, policy, rev=None)
    if args.range:
        findings += integrity.range_checks(root, policy, args.range)
    base = integrity.load_baseline(policy)
    meta = {"baseline_digest": integrity.baseline_digest(base) if base and not base.get("corrupt") else None,
            "current_digest": integrity.baseline_digest(integrity.snapshot(root, policy, rev=None)) if policy.protected_paths else None}
    return _finish(findings, policy, args, meta=meta, title=f"secure-check verify (baseline {meta['baseline_digest']}, now {meta['current_digest']})")


def cmd_keys(args) -> int:
    """Show key NAMES and value lengths of a JSON / dotenv / YAML-ish file. Never values."""
    p = Path(args.file)
    if not p.is_file():
        print(f"no such file: {p}", file=sys.stderr)
        return EXIT_ERROR
    text = p.read_text(encoding="utf-8", errors="replace")
    rows: list[tuple[str, str]] = []
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            for k, v in obj.items():
                rows.append((str(k), f"{type(v).__name__}({len(v) if isinstance(v, (str, list, dict)) else v if isinstance(v, (int, float, bool)) else '?'})"
                             if not isinstance(v, str) else f"str({len(v)} chars)"))
    except ValueError:
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            for sep in ("=", ":"):
                if sep in s:
                    k, v = s.split(sep, 1)
                    rows.append((k.strip().lstrip("export ").strip(), f"{len(v.strip().strip(chr(34)).strip(chr(39)))} chars"))
                    break
    print(f"{p}: {len(rows)} entries (values withheld)")
    for k, v in rows:
        print(f"  {k:40s} {v}")
    return EXIT_CLEAN


def cmd_install_hooks(args) -> int:
    from . import installer
    root = _root(args)
    changed = installer.install_git_hooks(root)
    print("hooks installed" if changed else "hooks already up to date")
    return EXIT_CLEAN


def cmd_init(args) -> int:
    from . import installer
    target = Path(args.target).resolve() if args.target else _root(args)
    print(installer.init(target, args.profile, force=args.force, workflow=not args.no_workflow,
                         agent=not args.no_agent, claude=not args.no_claude, baseline=not args.no_baseline,
                         vendor=not args.no_vendor))
    return EXIT_CLEAN


def cmd_hook(args) -> int:
    from . import hook
    return hook.main()


def cmd_session_start(args) -> int:
    from . import hook
    return hook.main(json.dumps({"hook_event_name": "SessionStart", "cwd": os.getcwd()}))


def cmd_pre_push(args) -> int:
    """git pre-push hook body: stdin lines '<local ref> <local sha> <remote ref> <remote sha>'."""
    root = _root(args)
    policy = load(root)
    sc = Scanner(policy)
    findings: list[Finding] = []
    zero = "0" * 40
    for line in sys.stdin.read().splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts
        if local_sha == zero:
            continue  # branch deletion
        if remote_sha == zero:
            rev_args: list[str] | str = [local_sha, "--not", "--remotes"]
            rng = None
        else:
            rev_args = f"{remote_sha}..{local_sha}"
            rng = rev_args
        hist, _ = gitscan.scan_history(root, sc, policy, rev_range=rev_args, max_commits=policy.max_commits)
        ref_findings = hist
        if rng:
            ref_findings += integrity.range_checks(root, policy, rng)
        findings += integrity.apply_owner_approval(dedupe(ref_findings), root, rev_args,
                                                   os.environ.get("SECURE_CHECK_OWNER") == "1")
    args.quiet_ok = True
    return _finish(findings, policy, args, title="secure-check pre-push")


def cmd_profiles(args) -> int:
    from .profiles import PROFILES
    if args.name:
        print(PROFILES[args.name])
    else:
        for k in PROFILES:
            print(k)
    return EXIT_CLEAN


# ---- parser ------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secure-check", description="A safety wall for repositories that AI agents commit to.")
    p.add_argument("--version", action="version", version=f"secure-check {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, fail=True):
        sp.add_argument("--root", help="path inside the repository (default: cwd)")
        sp.add_argument("--format", choices=["text", "json", "sarif", "github"], default="text")
        if fail:
            sp.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], help="override policy fail_on")
        sp.add_argument("--quiet-ok", action="store_true", help="print nothing when clean (for hooks)")

    s = sub.add_parser("scan", help="scan tracked files (default), the index (--staged), a push range, or paths")
    common(s)
    g = s.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true", help="what `git commit` would commit")
    g.add_argument("--range", help="A..B: every commit about to be pushed")
    s.add_argument("paths", nargs="*", help="files or directories (working tree)")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("history", help="scan git history for secrets ever committed")
    common(s)
    s.add_argument("--range", help="A..B instead of all refs")
    s.add_argument("--max-commits", type=int)
    s.set_defaults(func=cmd_history)

    s = sub.add_parser("audit", help="everything: files, gitignore, remotes, integrity, agent configs, history")
    common(s)
    s.add_argument("--no-history", action="store_true")
    s.add_argument("--max-commits", type=int)
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("baseline", help="record sha256 of protected files (owner action)")
    s.add_argument("--root")
    s.add_argument("--head", action="store_true", help="hash HEAD instead of the working tree")
    s.set_defaults(func=cmd_baseline)

    s = sub.add_parser("verify", help="compare protected files with the baseline")
    common(s)
    s.add_argument("--range", help="also run protected/append-only/immutable checks on A..B")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("keys", help="list key names and value lengths of a credential file (never values)")
    s.add_argument("file")
    s.set_defaults(func=cmd_keys)

    s = sub.add_parser("install-hooks", help="copy pre-commit/pre-push into .git/hooks")
    s.add_argument("--root")
    s.set_defaults(func=cmd_install_hooks)

    s = sub.add_parser("init", help="install the guard into a repository")
    s.add_argument("--target", help="repository root (default: current repo)")
    s.add_argument("--profile", default="default", help="default | content-creator | stock-master")
    s.add_argument("--force", action="store_true", help="overwrite policy, agent brief and workflow")
    s.add_argument("--no-workflow", action="store_true")
    s.add_argument("--no-agent", action="store_true")
    s.add_argument("--no-claude", action="store_true", help="do not touch .claude/settings.json")
    s.add_argument("--no-baseline", action="store_true")
    s.add_argument("--no-vendor", action="store_true", help="do not copy the tool into .secure-check/lib (for this repository itself)")
    s.add_argument("--root")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("fleet", help="audit EVERY repository you own (daily, from GitHub Actions) or a list of local paths")
    s.add_argument("--local", nargs="+", metavar="PATH", help="audit these local repositories instead of the GitHub account")
    s.add_argument("--owner", help="audit this user's PUBLIC repositories instead of the token owner's own")
    s.add_argument("--depth", type=int, default=500, help="clone depth (history scanned)")
    s.add_argument("--no-history", action="store_true")
    s.add_argument("--max-commits", type=int, default=500)
    s.add_argument("--new-days", type=int, default=7, help="a repository created within this many days is flagged NEW")
    s.add_argument("--dormant-days", type=int, default=90, help="no push for this long: a missing guard is a note, not a failure")
    s.add_argument("--workdir", help="where to clone (default: a temporary directory, removed afterwards)")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default="high")
    s.add_argument("--no-require-guard", action="store_true", help="do not fail when an active repository lacks the guard")
    s.add_argument("--details", choices=["auto", "always", "never"], default="auto",
                   help="show paths/fingerprints; auto withholds them when this run lives in a public repository")
    s.add_argument("--summary", help="append the markdown report to this file (e.g. $GITHUB_STEP_SUMMARY)")
    s.add_argument("--report", help="write the markdown report to this file")
    s.add_argument("--json", help="write full machine-readable results to this file")
    s.add_argument("--format", choices=["text", "github"], default="text")
    s.set_defaults(func=cmd_fleet)

    s = sub.add_parser("profiles", help="list or print policy profiles")
    s.add_argument("name", nargs="?")
    s.set_defaults(func=cmd_profiles)

    s = sub.add_parser("hook", help="Claude Code PreToolUse hook (reads JSON on stdin)")
    s.set_defaults(func=cmd_hook)
    s = sub.add_parser("session-start", help="Claude Code SessionStart hook")
    s.set_defaults(func=cmd_session_start)
    s = sub.add_parser("pre-push", help="git pre-push hook body")
    common(s)
    s.add_argument("git_args", nargs="*", help="remote name and url, passed by git")
    s.set_defaults(func=cmd_pre_push)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"secure-check: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR
