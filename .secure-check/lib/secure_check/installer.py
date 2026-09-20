"""``secure-check init``: put the whole wall into a target repository.

Idempotent. Re-running updates the vendored tool and leaves the owner's
policy, baseline and settings customisations alone unless ``--force``.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from . import templates
from .policy import DEFAULT_IGNORE_BLOCK, POLICY_FILENAME, load
from .profiles import PROFILES
from .util import _git_env

PKG_DIR = Path(__file__).resolve().parent
VENDOR_REL = Path(".secure-check")


def _write(path: Path, content: str, *, force: bool, log: list[str], mode: int | None = None) -> bool:
    if path.exists() and not force:
        if path.read_text(encoding="utf-8", errors="replace") == content:
            log.append(f"  = {path.name} (unchanged)")
        else:
            log.append(f"  ~ {path} exists; kept (use --force to overwrite)")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)
    log.append(f"  + {path}")
    return True


def vendor_package(target: Path, log: list[str]) -> Path:
    dest = target / VENDOR_REL / "lib" / "secure_check"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(PKG_DIR, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"))
    for junk in dest.rglob("__pycache__"):
        shutil.rmtree(junk, ignore_errors=True)
    log.append(f"  + {dest.relative_to(target)} (tool vendored)")
    return dest


def write_hooks(target: Path, log: list[str]) -> None:
    hooks = target / VENDOR_REL / "hooks"
    _write(hooks / "pre-commit", templates.PRE_COMMIT, force=True, log=log, mode=0o755)
    _write(hooks / "pre-push", templates.PRE_PUSH, force=True, log=log, mode=0o755)


def install_git_hooks(target: Path, *, quiet: bool = False) -> bool:
    """Copy the repo's hooks into .git/hooks (or core.hooksPath). Returns True if anything changed."""
    src = target / VENDOR_REL / "hooks"
    if not src.exists():
        raise FileNotFoundError(f"{src} missing; run `secure-check init` first")
    src_ok = (target / VENDOR_REL / "lib" / "secure_check").exists() or (target / "secure_check" / "cli.py").exists()
    if not src_ok:
        raise FileNotFoundError("no secure_check package found in .secure-check/lib or the repository root")
    git_dir = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=str(target), capture_output=True,
                             text=True, env=_git_env())
    if git_dir.returncode != 0:
        raise RuntimeError("not a git repository")
    common = Path(git_dir.stdout.strip())
    if not common.is_absolute():
        common = target / common
    hooks_path = subprocess.run(["git", "config", "--get", "core.hooksPath"], cwd=str(target),
                                capture_output=True, text=True, env=_git_env()).stdout.strip()
    dest_dir = (target / hooks_path) if hooks_path else (common / "hooks")
    dest_dir.mkdir(parents=True, exist_ok=True)
    changed = False
    for name in ("pre-commit", "pre-push"):
        content = (src / name).read_text(encoding="utf-8")
        dest = dest_dir / name
        if dest.exists():
            old = dest.read_text(encoding="utf-8", errors="replace")
            if old == content:
                continue
            if "secure-check" not in old:
                backup = dest.with_suffix(".pre-secure-check")
                shutil.copyfile(dest, backup)
                if not quiet:
                    print(f"  ~ existing {name} hook saved as {backup.name}")
        dest.write_text(content, encoding="utf-8")
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        changed = True
        if not quiet:
            print(f"  + {dest}")
    return changed


def merge_claude_settings(target: Path, log: list[str]) -> None:
    path = target / ".claude" / "settings.json"
    data: dict = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            backup = path.with_suffix(".json.broken")
            shutil.copyfile(path, backup)
            log.append(f"  ~ {path} was invalid JSON; saved as {backup.name} and replaced")
            data = {}
    hooks = data.setdefault("hooks", {})

    def ensure(event: str, matcher: str | None, command: str, timeout: int) -> None:
        groups = hooks.setdefault(event, [])
        for g in groups:
            for h in g.get("hooks", []):
                if "secure_check" in str(h.get("command", "")) and (matcher is None or g.get("matcher") == matcher):
                    h["command"] = command
                    h["timeout"] = timeout
                    return
        entry = {"hooks": [{"type": "command", "command": command, "timeout": timeout}]}
        if matcher is not None:
            entry["matcher"] = matcher
        groups.append(entry)

    ensure("PreToolUse", "Bash", templates.HOOK_COMMAND, 120)
    ensure("PreToolUse", "Write|Edit|MultiEdit|NotebookEdit", templates.HOOK_COMMAND, 60)
    ensure("SessionStart", None, templates.SESSION_START_COMMAND, 60)

    perms = data.setdefault("permissions", {})
    deny = perms.setdefault("deny", [])
    for rule in templates.DENY_RULES:
        if rule not in deny:
            deny.append(rule)
    if perms.get("defaultMode") == "bypassPermissions":
        del perms["defaultMode"]
        log.append("  ~ removed permissions.defaultMode=bypassPermissions")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    log.append(f"  + {path.relative_to(target)} (hooks + deny rules merged)")


def ensure_gitignore(target: Path, log: list[str]) -> None:
    gi = target / ".gitignore"
    existing = gi.read_text(encoding="utf-8") if gi.exists() else ""
    have = {ln.strip() for ln in existing.splitlines()}
    missing = [ln for ln in DEFAULT_IGNORE_BLOCK.splitlines()
               if ln.strip() and not ln.startswith("#") and ln.strip() not in have]
    if not missing:
        log.append("  = .gitignore already covers the standard block")
        return
    block = "\n# --- secure-check: credentials and local state must never be committed ---\n" + "\n".join(missing) + "\n"
    with gi.open("a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(block)
    log.append(f"  + .gitignore ({len(missing)} rules appended)")


def init(target: Path, profile: str, *, force: bool = False, workflow: bool = True, agent: bool = True,
         claude: bool = True, baseline: bool = True, vendor: bool = True) -> str:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile '{profile}'; choose from {', '.join(PROFILES)}")
    target = target.resolve()
    if not (target / ".git").exists():
        raise RuntimeError(f"{target} is not the root of a git repository")
    log: list[str] = [f"secure-check init -> {target} (profile: {profile})"]
    if vendor:
        vendor_package(target, log)
    else:
        log.append("  = tool not vendored (--no-vendor); hooks fall back to the repository root")
    write_hooks(target, log)
    _write(target / VENDOR_REL / "README.md", templates.VENDOR_README, force=True, log=log)
    _write(target / POLICY_FILENAME, PROFILES[profile], force=force, log=log)
    ensure_gitignore(target, log)
    try:
        install_git_hooks(target, quiet=True)
        log.append("  + .git/hooks/pre-commit, pre-push")
    except Exception as exc:
        log.append(f"  ! git hooks not installed: {exc}")
    if claude:
        merge_claude_settings(target, log)
    if agent:
        _write(target / ".claude" / "agents" / "security-guard.md", templates.GUARD_AGENT, force=force, log=log)
    if workflow:
        _write(target / ".github" / "workflows" / "secure-check.yml", templates.WORKFLOW, force=force, log=log)
    if baseline:
        from . import integrity
        pol = load(target)
        if pol.protected_paths:
            path, digest = integrity.write_baseline(target, pol, rev=None)
            log.append(f"  + {path.relative_to(target)} (baseline digest {digest}; keep this digest somewhere outside the repo)")
    log.append("Next: review the diff, then `git add -A && git commit -m 'Add secure-check guard'`.")
    return "\n".join(log)
