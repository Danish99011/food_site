"""Policy file: ``.secure-check.toml`` at the repository root.

Everything has a default, so a repo with no policy file still gets the full
guard. The file exists to (a) allow-list known fakes, (b) name the files that
must never change without the owner, (c) tune severity.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

POLICY_FILENAME = ".secure-check.toml"

# Paths that MUST be ignored by .gitignore. Checked with `git check-ignore`, so
# they are tested against the real rules rather than string-matched.
DEFAULT_CANARIES = [
    ".env",
    ".env.local",
    ".env.production",
    "config/.env",
    "upload/token.json",
    "upload/token.json.bak",
    "upload/token.device.json",
    "token.json",
    "tokens.json",
    "oauth_token.json",
    "client_secret.json",
    "client_secret_123.apps.googleusercontent.com.json",
    "desktop_client.json",
    "credentials.json",
    "service-account.json",
    "service_account.json",
    ".secrets/anything.json",
    "secrets.json",
    "secrets.yaml",
    "id_rsa",
    "server.pem",
    "private.key",
    "keystore.p12",
    "cert.pfx",
    "anything.bak",
    ".netrc",
    ".pypirc",
    ".git-credentials",
    "data/anything.jsonl",
]

# .gitignore lines the installer appends when a canary is not ignored.
DEFAULT_IGNORE_BLOCK = """
# --- secure-check: credentials and local state must never be committed ---
.env
.env.*
!.env.example
!.env.sample
!.env.template
*.bak
*.orig
*.swp
**/token*.json
**/token*.json.*
**/*token*.json
**/*token*.json.*
**/client_secret*.json
**/desktop_client*.json
**/credentials.json
**/service-account*.json
**/service_account*.json
**/*-sa.json
.secrets/
secrets.json
secrets.yaml
secrets.yml
*.pem
*.key
!*.pub
*.p12
*.pfx
*.jks
*.keystore
id_rsa*
id_dsa*
id_ecdsa*
id_ed25519*
.netrc
.pypirc
.npmrc
.git-credentials
data/
*.sqlite
*.sqlite3
*.db
__pycache__/
*.pyc
""".strip("\n")


@dataclass
class Policy:
    root: Path
    fail_on: str = "high"
    # secrets
    allow_paths: list[str] = field(default_factory=list)
    allow_patterns: list[str] = field(default_factory=list)
    allow_fingerprints: list[str] = field(default_factory=list)
    disable_rules: list[str] = field(default_factory=list)
    max_file_bytes: int = 5_000_000
    # files
    extra_dangerous_files: list[str] = field(default_factory=list)
    allow_files: list[str] = field(default_factory=lambda: [".env.example", ".env.sample", ".env.template"])
    # gitignore
    canaries: list[str] = field(default_factory=lambda: list(DEFAULT_CANARIES))
    # integrity
    protected_paths: list[str] = field(default_factory=list)
    append_only_paths: list[str] = field(default_factory=list)
    immutable_paths: list[str] = field(default_factory=list)
    baseline_path: str = ".secure-check/baseline.json"
    # history
    max_commits: int = 3000
    # agents / hooks
    require_claude_hooks: bool = True
    require_git_hooks: bool = True
    block_force_push: bool = True
    block_direct_push_to: list[str] = field(default_factory=list)  # e.g. ["main"]; empty = allowed
    # network egress the repo is expected to talk to (informational for the agent audit)
    expected_hosts: list[str] = field(default_factory=list)

    @property
    def file(self) -> Path:
        return self.root / POLICY_FILENAME

    @property
    def baseline_file(self) -> Path:
        return self.root / self.baseline_path


def load(root: Path) -> Policy:
    pol = Policy(root=root)
    f = root / POLICY_FILENAME
    if not f.exists():
        return pol
    try:
        data = tomllib.loads(f.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise RuntimeError(f"{POLICY_FILENAME}: {exc}") from exc

    top = data.get("secure_check", {})
    pol.fail_on = top.get("fail_on", pol.fail_on)

    s = data.get("secrets", {})
    pol.allow_paths = list(s.get("allow_paths", []))
    pol.allow_patterns = list(s.get("allow_patterns", []))
    pol.allow_fingerprints = [x.lower() for x in s.get("allow_fingerprints", [])]
    pol.disable_rules = list(s.get("disable_rules", []))
    pol.max_file_bytes = int(s.get("max_file_bytes", pol.max_file_bytes))

    fl = data.get("files", {})
    pol.extra_dangerous_files = list(fl.get("extra_dangerous", []))
    pol.allow_files = list(fl.get("allow_paths", pol.allow_files))

    g = data.get("gitignore", {})
    if "canaries" in g:
        pol.canaries = list(g["canaries"])
    pol.canaries += list(g.get("extra_canaries", []))

    i = data.get("integrity", {})
    pol.protected_paths = list(i.get("protected_paths", []))
    pol.append_only_paths = list(i.get("append_only_paths", []))
    pol.immutable_paths = list(i.get("immutable_paths", []))
    pol.baseline_path = i.get("baseline", pol.baseline_path)

    h = data.get("history", {})
    pol.max_commits = int(h.get("max_commits", pol.max_commits))

    a = data.get("agents", {})
    pol.require_claude_hooks = bool(a.get("require_claude_hooks", True))
    pol.require_git_hooks = bool(a.get("require_git_hooks", True))
    pol.block_force_push = bool(a.get("block_force_push", True))
    pol.block_direct_push_to = list(a.get("block_direct_push_to", []))
    pol.expected_hosts = list(a.get("expected_hosts", []))
    return pol
