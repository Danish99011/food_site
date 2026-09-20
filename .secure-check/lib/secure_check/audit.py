"""The full audit of one repository, as a function (the CLI and the fleet check share it)."""
from __future__ import annotations

from pathlib import Path

from . import agents, files as filecheck, gitscan, integrity, repo as repocheck
from .findings import Finding, dedupe
from .policy import Policy
from .secrets import Scanner


def collect(root: Path, policy: Policy, *, history: bool = True, max_commits: int | None = None) -> tuple[list[Finding], int]:
    """Every check secure-check knows, over one repository. Returns (findings, commits scanned)."""
    sc = Scanner(policy)
    findings: list[Finding] = []
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
    findings += repocheck.remotes(root)
    findings += repocheck.tracked_but_ignored(root)
    findings += repocheck.gitignore_canaries(root, policy)
    findings += repocheck.large_tracked(root)
    findings += repocheck.hooks_installed(root, policy)
    findings += repocheck.committers(root)
    findings += integrity.verify(root, policy, rev=None)
    findings += agents.audit(root, policy, sc)
    n = 0
    if history:
        hist, n = gitscan.scan_history(root, sc, policy, all_refs=True, max_commits=max_commits or policy.max_commits)
        findings += hist
    return dedupe(findings), n
