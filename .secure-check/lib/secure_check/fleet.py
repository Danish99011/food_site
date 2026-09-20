"""Fleet audit: every repository the owner has, every day, including the one created yesterday.

Runs from GitHub Actions on a schedule (see .github/workflows/fleet-audit.yml) with a
read-only fine-grained token, or locally against paths with ``--local``.

For each repository it answers five questions:

1. Is the guard installed (``.secure-check.toml``)?
2. Does the repository run its own daily secure-check workflow, and did the last run pass?
3. Does a full ``secure-check audit`` of a fresh clone find anything?
4. Is there a ``secure-check/guard`` branch pushed but not merged?
5. Is the repository new (created recently) and therefore probably unguarded?

Secrets never appear in the output: findings carry a redacted preview and a fingerprint.
When the audit itself runs inside a PUBLIC repository, file paths and fingerprints are
withheld too (counts only), because the run log would be world-readable.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import audit as auditmod
from .findings import SEVERITIES, Finding, at_or_above, rank
from .policy import POLICY_FILENAME, load
from .util import _git_env

API = "https://api.github.com"
TOKEN_ENVS = ("FLEET_TOKEN", "SECURE_CHECK_FLEET_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")
GUARD_BRANCH = "secure-check/guard"
WORKFLOW_FILE = "secure-check.yml"

TOKEN_HELP = """No token found. The fleet audit needs a READ-ONLY fine-grained token in one of:
  FLEET_TOKEN (preferred), SECURE_CHECK_FLEET_TOKEN, GH_TOKEN, GITHUB_TOKEN
Create it once at https://github.com/settings/personal-access-tokens/new :
  Resource owner: you.  Repository access: All repositories (so new repos are covered).
  Repository permissions: Contents = Read-only, Metadata = Read-only, Actions = Read-only.
  Expiration: 1 year.  Then add it to the Secure-check repository as an Actions secret
  named FLEET_TOKEN (Settings -> Secrets and variables -> Actions -> New repository secret).
See docs/DAILY-CHECK.md."""


@dataclass
class RepoStatus:
    full_name: str
    private: bool | None = None
    default_branch: str = "main"
    archived: bool = False
    empty: bool = False
    created_at: str = ""
    pushed_at: str = ""
    is_new: bool = False
    dormant: bool = False
    guarded: bool | None = None
    workflow: bool | None = None
    last_run: str | None = None
    last_run_at: str | None = None
    guard_branch_waiting: bool = False
    findings: list[Finding] = field(default_factory=list)
    history_commits: int = 0
    error: str | None = None

    @property
    def name(self) -> str:
        return self.full_name.rsplit("/", 1)[-1]

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


# ---- GitHub API (stdlib) ----------------------------------------------------------
def token_from_env() -> str | None:
    for name in TOKEN_ENVS:
        v = os.environ.get(name, "").strip()
        if v:
            return v
    return None


def _api(path: str, token: str, params: dict | None = None):
    url = API + path + (("?" + urllib.parse.urlencode(params)) if params else "")
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "secure-check-fleet",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _api_optional(path: str, token: str, params: dict | None = None):
    """None on 404/403 (a missing workflow, no Actions permission), raise otherwise."""
    try:
        return _api(path, token, params)
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404):
            return None
        raise


def list_repos(token: str, owner: str | None = None) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        if owner:
            batch = _api(f"/users/{owner}/repos", token, {"per_page": 100, "page": page, "type": "owner"})
        else:
            batch = _api("/user/repos", token, {"per_page": 100, "page": page, "affiliation": "owner", "sort": "pushed"})
        out += batch
        if len(batch) < 100:
            break
        page += 1
    return out


def workflow_status(full_name: str, token: str) -> tuple[bool, str | None, str | None]:
    """(has secure-check workflow, last conclusion, last run time)."""
    wf = _api_optional(f"/repos/{full_name}/actions/workflows", token, {"per_page": 100})
    if not wf:
        return False, None, None
    match = [w for w in wf.get("workflows", []) if w.get("path", "").endswith(WORKFLOW_FILE) or w.get("name") == "secure-check"]
    if not match:
        return False, None, None
    runs = _api_optional(f"/repos/{full_name}/actions/workflows/{match[0]['id']}/runs", token, {"per_page": 1})
    if not runs or not runs.get("workflow_runs"):
        return True, "never ran", None
    r = runs["workflow_runs"][0]
    return True, (r.get("conclusion") or r.get("status") or "?"), r.get("created_at")


def guard_branch_exists(full_name: str, token: str) -> bool:
    b = _api_optional(f"/repos/{full_name}/branches/{urllib.parse.quote(GUARD_BRANCH, safe='')}", token)
    return bool(b)


def clone(full_name: str, token: str | None, dest: Path, depth: int) -> None:
    """Shallow clone with the token passed as an HTTP header via environment, never in the URL
    (a URL token would be written into .git/config and would trip our own remote check)."""
    env = _git_env()
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraheader",
                    "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"})
    proc = subprocess.run(["git", "clone", "--quiet", "--no-tags", f"--depth={depth}",
                           f"https://github.com/{full_name}", str(dest)],
                          capture_output=True, text=True, env=env, timeout=900)
    if proc.returncode != 0:
        err = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "clone failed"
        raise RuntimeError(err[:200])


# ---- the audit of one repo ---------------------------------------------------------
def audit_clone(root: Path, st: RepoStatus, *, history: bool, max_commits: int) -> None:
    st.guarded = (root / POLICY_FILENAME).exists()
    if st.workflow is None:
        st.workflow = (root / ".github" / "workflows" / WORKFLOW_FILE).exists()
    try:
        policy = load(root)
        st.findings, st.history_commits = auditmod.collect(root, policy, history=history, max_commits=max_commits)
    except Exception as exc:  # one broken repo must not hide the others
        st.error = f"{type(exc).__name__}: {str(exc)[:160]}"


def _age_days(iso: str) -> float | None:
    if not iso:
        return None
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 86400


def run_remote(token: str, *, owner: str | None, depth: int, history: bool, max_commits: int,
               new_days: int, dormant_days: int, workdir: Path, log=print) -> list[RepoStatus]:
    repos = list_repos(token, owner)
    log(f"fleet: {len(repos)} repositories")
    statuses: list[RepoStatus] = []
    for r in sorted(repos, key=lambda x: x.get("pushed_at") or "", reverse=True):
        st = RepoStatus(full_name=r["full_name"], private=bool(r.get("private")), default_branch=r.get("default_branch") or "main",
                        archived=bool(r.get("archived")), empty=(r.get("size", 0) == 0),
                        created_at=r.get("created_at") or "", pushed_at=r.get("pushed_at") or "")
        age_created = _age_days(st.created_at)
        age_pushed = _age_days(st.pushed_at)
        st.is_new = age_created is not None and age_created <= new_days
        st.dormant = age_pushed is not None and age_pushed >= dormant_days
        statuses.append(st)
        if st.archived or st.empty:
            log(f"  {st.full_name}: {'archived' if st.archived else 'empty'}, skipped")
            continue
        try:
            st.workflow, st.last_run, st.last_run_at = workflow_status(st.full_name, token)
            st.guard_branch_waiting = guard_branch_exists(st.full_name, token)
        except Exception as exc:
            st.error = f"api: {type(exc).__name__}: {str(exc)[:120]}"
        dest = workdir / st.name
        try:
            clone(st.full_name, token, dest, depth)
            audit_clone(dest, st, history=history, max_commits=max_commits)
        except Exception as exc:
            st.error = (st.error + "; " if st.error else "") + f"clone/audit: {str(exc)[:160]}"
        finally:
            shutil.rmtree(dest, ignore_errors=True)
        c = st.counts()
        log(f"  {st.full_name}: guard={'yes' if st.guarded else 'NO'} workflow={'yes' if st.workflow else 'no'} "
            f"last={st.last_run or '-'} findings={c['critical']}c/{c['high']}h/{c['medium']}m"
            + (f" ERROR {st.error}" if st.error else ""))
    return statuses


def run_local(paths: list[Path], *, history: bool, max_commits: int, log=print) -> list[RepoStatus]:
    statuses = []
    for p in paths:
        p = p.resolve()
        st = RepoStatus(full_name=p.name)
        if not (p / ".git").exists():
            st.error = "not a git repository"
            statuses.append(st)
            continue
        audit_clone(p, st, history=history, max_commits=max_commits)
        statuses.append(st)
        c = st.counts()
        log(f"  {p.name}: guard={'yes' if st.guarded else 'NO'} findings={c['critical']}c/{c['high']}h/{c['medium']}m"
            + (f" ERROR {st.error}" if st.error else ""))
    return statuses


# ---- verdict and report ---------------------------------------------------------------
def verdict(statuses: list[RepoStatus], *, fail_on: str, require_guard: bool) -> tuple[bool, list[str]]:
    """(ok, reasons)."""
    reasons: list[str] = []
    for st in statuses:
        if st.archived or st.empty:
            continue
        if st.error:
            reasons.append(f"{st.name}: could not be audited ({st.error})")
        bad = at_or_above(st.findings, fail_on)
        if bad:
            reasons.append(f"{st.name}: {len(bad)} finding(s) at or above {fail_on}")
        if require_guard and st.guarded is False and not st.dormant:
            reasons.append(f"{st.name}: guard not installed" + (" (NEW repository)" if st.is_new else ""))
        if st.workflow and st.last_run not in (None, "success", "never ran"):
            reasons.append(f"{st.name}: its own daily check last ended '{st.last_run}'")
    return (not reasons), reasons


def render_markdown(statuses: list[RepoStatus], *, details: bool, fail_on: str, reasons: list[str]) -> str:
    ok = not reasons
    lines = [f"# Fleet audit: {'all clear' if ok else 'ATTENTION'}",
             "",
             f"_{dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · {len(statuses)} repositories · fail on {fail_on}_",
             ""]
    if reasons:
        lines.append("## What needs you")
        lines += [f"- {r}" for r in reasons]
        lines.append("")
    lines.append("| Repository | Visibility | Guard | Daily check | Last run | Crit / High / Med | Notes |")
    lines.append("|---|---|---|---|---|---|---|")
    for st in statuses:
        vis = "private" if st.private else ("public" if st.private is False else "?")
        if st.archived:
            row_note = "archived"
        elif st.empty:
            row_note = "empty"
        else:
            notes = []
            if st.is_new:
                notes.append("**NEW**")
            if st.dormant:
                notes.append("dormant")
            if st.guard_branch_waiting:
                notes.append(f"`{GUARD_BRANCH}` branch waiting to be merged")
            if st.error:
                notes.append(f"error: {st.error}")
            row_note = ", ".join(notes)
        c = st.counts()
        guard = "-" if st.guarded is None else ("yes" if st.guarded else "**NO**")
        wf = "-" if st.workflow is None else ("yes" if st.workflow else "no")
        run = st.last_run or "-"
        lines.append(f"| {st.full_name} | {vis} | {guard} | {wf} | {run} | {c['critical']} / {c['high']} / {c['medium']} | {row_note} |")
    lines.append("")
    if details:
        for st in statuses:
            shown = [f for f in st.findings if rank(f.severity) >= rank("medium")]
            if not shown:
                continue
            lines.append(f"## {st.full_name}")
            for f in shown[:15]:
                where = f.path + (f":{f.line}" if f.line else "") + (f" @ {f.commit}" if f.commit else "")
                extra = f" · fp `{f.fingerprint}`" if f.fingerprint else ""
                lines.append(f"- **{f.severity}** `{f.rule}` {where}{extra}: {f.message}")
            if len(shown) > 15:
                lines.append(f"- … {len(shown) - 15} more; run `secure-check audit` in the repository")
            lines.append("")
    else:
        lines.append("_Finding details withheld: this audit ran inside a PUBLIC repository, where the log is "
                     "world-readable. Make the Secure-check repository private to see paths and fingerprints, "
                     "or run `secure-check audit` inside each repository._")
        lines.append("")
    lines.append("Fix an unguarded repository with `python3 -m secure_check init --profile default` from the "
                 "Secure-check checkout; a finding's fix is in `docs/INCIDENT-RUNBOOK.md`.")
    return "\n".join(lines)


def running_in_public_repo(token: str | None) -> bool | None:
    """True/False when we can tell where this run lives, None otherwise."""
    full = os.environ.get("GITHUB_REPOSITORY")
    if not full or not token:
        return None
    try:
        info = _api(f"/repos/{full}", token)
    except Exception:
        return None
    return not bool(info.get("private"))


def main(args) -> int:
    from . import report as reportmod
    fail_on = args.fail_on or "high"
    if args.local:
        statuses = run_local([Path(p) for p in args.local], history=not args.no_history, max_commits=args.max_commits, log=print)
        details = args.details != "never"
    else:
        token = token_from_env()
        if not token:
            print(TOKEN_HELP, file=sys.stderr)
            return 2
        workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="fleet-"))
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            statuses = run_remote(token, owner=args.owner, depth=args.depth, history=not args.no_history,
                                  max_commits=args.max_commits, new_days=args.new_days, dormant_days=args.dormant_days,
                                  workdir=workdir, log=print)
        except urllib.error.HTTPError as exc:
            print(f"fleet: GitHub API {exc.code} for {exc.url}: check the token's permissions "
                  f"(Contents/Metadata/Actions read on all repositories)", file=sys.stderr)
            return 2
        finally:
            if not args.workdir:
                shutil.rmtree(workdir, ignore_errors=True)
        if args.details == "always":
            details = True
        elif args.details == "never":
            details = False
        else:
            details = running_in_public_repo(token) is not True
    ok, reasons = verdict(statuses, fail_on=fail_on, require_guard=not args.no_require_guard)
    md = render_markdown(statuses, details=details, fail_on=fail_on, reasons=reasons)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    if args.report:
        Path(args.report).write_text(md + "\n", encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps([{**{k: v for k, v in st.__dict__.items() if k != "findings"},
                                                 "counts": st.counts(),
                                                 "findings": [f.to_dict() for f in st.findings] if details else []}
                                                for st in statuses], indent=2), encoding="utf-8")
    print()
    print(md if args.format != "github" else md)
    if args.format == "github":
        for r in reasons:
            print(f"::error title=fleet-audit::{r}")
        if ok:
            print("::notice title=fleet-audit::all clear")
    print()
    print("fleet: " + ("ALL CLEAR" if ok else "ATTENTION: " + "; ".join(reasons)))
    return 0 if ok else 1
