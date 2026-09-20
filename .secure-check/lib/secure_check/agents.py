"""Audit of the AI-agent control plane: Claude Code settings, agent briefs,
CLAUDE.md, MCP config, GitHub workflows.

The question each check answers: *what can an agent do without the owner,
and would anyone notice?*
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .findings import Finding
from .policy import Policy
from .secrets import Scanner

RISKY_VERBS = re.compile(r"\b(upload|deploy|pay|spend|purchase|force[- ]push|rm -rf|"
                         r"place[sd]? (?:an? |the )?(?:live )?orders?|submit[s]? (?:an? |the )?orders?|live trad(?:e|ing)|"
                         r"transfer money|wire|delete[s]? (?:the )?(?:video|channel|data|history|repo))\b", re.I)
GATE_WORDS = re.compile(r"(owner'?s? (explicit )?(go|approval|word|ok)|explicit(ly)? approv|written approval|"
                        r"never (upload|push|publish|spend|delete) without|do not .* without the owner|"
                        r"confirm with the owner|ask the owner|escalat|dry[- ]run first)", re.I)
BROAD_ALLOW = [
    (re.compile(r"^Bash(\(\*\)|\(:\*\))?$"), "high", "allows every shell command without a prompt"),
    (re.compile(r"^Bash\(git push[^)]*\)$"), "medium", "pre-approves git push"),
    (re.compile(r"^Bash\(rm [^)]*\)$"), "high", "pre-approves rm"),
    (re.compile(r"^Bash\((curl|wget)[^)]*\)$"), "medium", "pre-approves outbound transfers"),
    (re.compile(r"^(Write|Edit)(\(\*\)|\(\*\*\))?$"), "medium", "pre-approves every file write"),
]
WANT_DENY = ["Read(./.env)", "Read(./.env.*)", "Read(./.secrets/**)"]


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    fm: dict[str, str] = {}
    for line in text[3:end].splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$", line)
        if m:
            fm[m.group(1).strip()] = m.group(2).strip()
    return fm


def audit(root: Path, policy: Policy, scanner: Scanner) -> list[Finding]:
    out: list[Finding] = []
    out += _settings(root, policy)
    out += _agent_briefs(root)
    out += _instructions(root)
    out += _mcp(root, scanner)
    out += _workflows(root)
    return out


def _settings(root: Path, policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    guard_hook = False
    any_settings = False
    for name in (".claude/settings.json", ".claude/settings.local.json"):
        f = root / name
        if not f.exists():
            continue
        any_settings = True
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            out.append(Finding("claude_settings_invalid", "medium", name, "settings file is not valid JSON",
                               fix="Fix the JSON; Claude Code ignores a broken file, including its deny list."))
            continue
        perms = data.get("permissions", {}) or {}
        if perms.get("defaultMode") == "bypassPermissions":
            out.append(Finding("claude_bypass_permissions", "critical", name,
                               "defaultMode is bypassPermissions: every tool call runs without a prompt",
                               fix="Remove defaultMode or set it to 'default'/'acceptEdits'."))
        for rule in perms.get("allow", []) or []:
            for rx, sev, why in BROAD_ALLOW:
                if rx.match(str(rule).strip()):
                    out.append(Finding("claude_broad_allow", sev, name, f"allow rule '{rule}' {why}",
                                       fix="Narrow the rule to the exact commands the project needs."))
        deny = [str(d) for d in (perms.get("deny", []) or [])]
        missing = [w for w in WANT_DENY if w not in deny]
        if missing and name.endswith("settings.json"):
            out.append(Finding("claude_deny_missing", "medium", name,
                               f"deny list lacks secret-file reads: {', '.join(missing)}",
                               fix="Add them under permissions.deny so an agent cannot read or edit credentials "
                                   "(and cannot paste them into a transcript)."))
        if data.get("enableAllProjectMcpServers") is True:
            out.append(Finding("claude_mcp_auto_enable", "medium", name,
                               "enableAllProjectMcpServers=true trusts any .mcp.json committed to the repo",
                               fix="Set it to false and approve servers one by one."))
        hooks = data.get("hooks", {}) or {}
        for group in hooks.get("PreToolUse", []) or []:
            if "Bash" in str(group.get("matcher", "")):
                for h in group.get("hooks", []) or []:
                    if "secure" in str(h.get("command", "")) and "check" in str(h.get("command", "")):
                        guard_hook = True
    if policy.require_claude_hooks and not guard_hook:
        out.append(Finding("claude_guard_hook_missing", "medium", ".claude/settings.json",
                           "No PreToolUse hook runs secure-check before git commit/push" +
                           ("" if any_settings else " (no project settings file at all)"),
                           fix="Run `secure-check init` in this repo; it installs the hook."))
    return out


def _agent_briefs(root: Path) -> list[Finding]:
    out: list[Finding] = []
    for f in sorted((root / ".claude" / "agents").glob("*.md")) if (root / ".claude" / "agents").exists() else []:
        text = f.read_text(encoding="utf-8", errors="replace")
        fm = _frontmatter(text)
        rel = str(f.relative_to(root))
        if not fm.get("name"):
            continue
        if fm.get("permissionMode") == "bypassPermissions":
            out.append(Finding("agent_bypass_permissions", "critical", rel,
                               f"agent '{fm['name']}' runs with bypassPermissions",
                               fix="Remove permissionMode; let the session's permission mode apply."))
        tools = fm.get("tools", "")
        has_bash = "Bash" in tools or (not tools and "disallowedTools" not in fm)
        body = text.split("\n---", 2)[-1]
        risky = RISKY_VERBS.search(fm.get("description", ""))
        if has_bash and risky and not GATE_WORDS.search(text):
            out.append(Finding("agent_no_approval_gate", "low", rel,
                               f"agent '{fm['name']}' has Bash and talks about '{risky.group(0)}' but its brief "
                               f"states no owner-approval gate",
                               fix="Add an explicit rule: the action needs the owner's current, specific go; "
                                   "dry-run first; report before acting."))
    return out


def _instructions(root: Path) -> list[Finding]:
    out: list[Finding] = []
    cands = [root / "CLAUDE.md", root / "AGENTS.md"]
    if (root / ".claude").exists():
        cands += sorted((root / ".claude").glob("**/*.md"))
    if (root / "docs").exists():
        cands += sorted((root / "docs").glob("**/*.md"))
    seen_direct = False
    # phrasing that marks a mention as documentation/prohibition rather than an order to an agent
    _safe_ctx = re.compile(r"(?i)never|do not|don'?t|owner[- ]only|SECURE_CHECK_OWNER|forbidden|refuse|purge|"
                           r"blocked|not allowed|must not|rewrite history is")
    for f in cands:
        if not f.exists() or not f.is_file():
            continue
        rel = str(f.relative_to(root))
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_fence = False
        for i, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            if re.search(r"git push[^\n]*(--force\b|-f\b|--force-with-lease)", line) and not _safe_ctx.search(line):
                out.append(Finding("instructions_force_push", "low", rel, "Instructions mention force-pushing",
                                   line=i, fix="Agents must never rewrite shared history. Remove the instruction; "
                                                "protect the branch on GitHub."))
            if not seen_direct and re.search(r"git push\s+\S+\s+HEAD:(master|main)\b", line):
                seen_direct = True
                out.append(Finding("instructions_direct_push_default", "low", rel,
                                   "Agents are instructed to push straight to the default branch",
                                   line=i, fix="That is a workflow choice. Make it safe: a GitHub ruleset that "
                                                "blocks force-push and deletion, plus the secure-check CI guard "
                                                "that fails (and emails you) on secrets or protected-path changes."))
            if re.search(r"(print|echo|cat)\b[^\n]*\$?\{?[A-Z_]*(API_KEY|SECRET|TOKEN)\b", line) and "never" not in line.lower():
                out.append(Finding("instructions_echo_secret", "medium", rel, "Instructions echo a secret-named variable",
                                   line=i, fix="Print `<set>`/`<unset>` instead of the value."))
    return out


def _mcp(root: Path, scanner: Scanner) -> list[Finding]:
    out: list[Finding] = []
    f = root / ".mcp.json"
    if not f.exists():
        return out
    text = f.read_text(encoding="utf-8", errors="replace")
    out += scanner.scan_text(text, ".mcp.json")
    try:
        data = json.loads(text)
    except ValueError:
        return out
    for name, srv in (data.get("mcpServers", {}) or {}).items():
        for k, v in (srv.get("env", {}) or {}).items():
            if isinstance(v, str) and v and not v.startswith("${"):
                if re.search(r"(KEY|SECRET|TOKEN|PASS)", k, re.I):
                    out.append(Finding("mcp_inline_secret", "high", ".mcp.json",
                                       f"server '{name}' sets {k} inline instead of ${{{k}}}",
                                       fix="Reference the environment variable; never commit the value."))
    return out


def _workflows(root: Path) -> list[Finding]:
    out: list[Finding] = []
    wf = root / ".github" / "workflows"
    if not wf.exists():
        return out
    for f in sorted(list(wf.glob("*.yml")) + list(wf.glob("*.yaml"))):
        rel = str(f.relative_to(root))
        text = f.read_text(encoding="utf-8", errors="replace")
        if "pull_request_target" in text and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
            out.append(Finding("workflow_pwn_request", "critical", rel,
                               "pull_request_target checks out the PR head: a stranger's PR runs with your secrets",
                               fix="Use pull_request, or never check out the PR head under pull_request_target."))
        if re.search(r"permissions:\s*write-all", text):
            out.append(Finding("workflow_write_all", "medium", rel, "permissions: write-all",
                               fix="Grant only the scopes the job needs (contents: read is usually enough)."))
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"\$\{\{\s*github\.event\.(issue|comment|pull_request|review|discussion)\.(title|body)", line) or \
               re.search(r"\$\{\{\s*github\.head_ref", line):
                if "run:" in text:
                    out.append(Finding("workflow_script_injection", "high", rel,
                                       "Untrusted event text interpolated into the workflow (script injection)",
                                       line=i, fix="Pass it through an env: variable and quote it in the script."))
            if re.search(r"echo[^\n]*\$\{\{\s*secrets\.", line):
                out.append(Finding("workflow_echo_secret", "high", rel, "Workflow echoes a secret", line=i,
                                   fix="Never print secrets; GitHub masks known ones but not transformed values."))
            m = re.search(r"uses:\s*([^\s@]+)@(main|master|latest)\b", line)
            if m and not m.group(1).startswith(("actions/", "github/")):
                out.append(Finding("workflow_unpinned_action", "low", rel,
                                   f"third-party action {m.group(1)} pinned to a moving ref", line=i,
                                   fix="Pin to a full commit SHA."))
    return out
