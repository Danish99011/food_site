"""Per-repository policy profiles written by ``secure-check init --profile``.

Kept as TOML text so the vendored copy of this package carries them.
"""

PROFILES: dict[str, str] = {}

PROFILES["default"] = """# secure-check policy. Docs: https://github.com/Danish99011/Secure-check
[secure_check]
fail_on = "high"          # critical|high|medium|low -- lowest severity that fails a run

[secrets]
allow_paths = []          # globs never scanned for secrets (test fixtures only)
allow_patterns = []       # regexes; a matched VALUE is ignored
allow_fingerprints = []   # sha256 prefixes (>=8 hex) of known fakes, from the report
disable_rules = []        # pattern ids to switch off

[files]
extra_dangerous = []      # regexes on the repo-relative path
allow_paths = [".env.example", ".env.sample", ".env.template"]

[gitignore]
extra_canaries = []       # more paths that must be ignored

[integrity]
# Files that change only with the owner's explicit approval. Any change is a
# finding in `verify`, in the pre-push hook and in CI.
protected_paths = [
  ".claude/**",
  "CLAUDE.md",
  ".github/workflows/**",
  ".secure-check.toml",
  ".secure-check/**",
]
# Files that may only grow (ledgers, scoreboards). A removed line is critical.
append_only_paths = []
# Files that, once committed, are never modified or deleted (archives).
immutable_paths = []

[history]
max_commits = 3000

[agents]
require_claude_hooks = true
require_git_hooks = true
block_force_push = true
block_direct_push_to = []   # e.g. ["main"] to force pull requests
"""

PROFILES["content-creator"] = """# secure-check policy for the Content-creator (YouTube pipeline) repository.
[secure_check]
fail_on = "high"

[secrets]
allow_paths = []
allow_patterns = []
allow_fingerprints = []
disable_rules = []

[files]
extra_dangerous = ["^upload/.*token.*", "^upload/.*client.*\\\\.json", "^\\\\.secrets/"]
allow_paths = [".env.example", ".env.sample", ".env.template"]

[gitignore]
extra_canaries = ["upload/desktop_client.json", ".secrets/service-account.json"]

[integrity]
# The YouTube door, the money door, and the agents' own rulebook.
protected_paths = [
  ".claude/**",
  "CLAUDE.md",
  "docs/STANDARDS.md",
  "finance/budget.json",
  "finance/spend.py",
  "upload/auth.py",
  "upload/youtube_client.py",
  "upload/publish_episode.py",
  "upload/apply_channel_base.py",
  "generate/gemini.py",
  "storage/media.py",
  ".github/workflows/**",
  ".secure-check.toml",
  ".secure-check/**",
]
append_only_paths = ["finance/spend.jsonl"]
immutable_paths = []

[history]
max_commits = 3000

[agents]
require_claude_hooks = true
require_git_hooks = true
block_force_push = true
block_direct_push_to = []
expected_hosts = [
  "oauth2.googleapis.com", "www.googleapis.com", "youtube.googleapis.com",
  "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
  "storage.googleapis.com", "texttospeech.googleapis.com",
]
"""

PROFILES["stock-master"] = """# secure-check policy for the Stock-master (market analysis agents) repository.
[secure_check]
fail_on = "high"

[secrets]
allow_paths = []
allow_patterns = []
allow_fingerprints = []
disable_rules = []

[files]
extra_dangerous = []
allow_paths = [".env.example", ".env.sample", ".env.template"]

[gitignore]
extra_canaries = ["data/advisory_results.json", "data/trades.jsonl", "data/equity_curve.jsonl"]

[integrity]
# Risk limits, capital basis, agent roles, the company handbook, watchlist: owner-only changes.
# CLAUDE.md is deliberately NOT protected here: it is the nightly hand-off document that the
# scribe role rewrites, and an unattended Routine cannot answer an approval prompt.
# docs/backlog.md is not protected either (Stocky updates Status lines by design).
protected_paths = [
  "stock_master/risk/**",
  "stock_master/config.py",
  "stock_master/execution/**",
  ".claude/**",
  "docs/company.md",
  "watchlist.txt",
  ".github/workflows/**",
  ".secure-check.toml",
  ".secure-check/**",
]
# The proprietary track record: it may grow, never shrink or be rewritten.
append_only_paths = ["scoreboard/*.jsonl"]
# Archived daily reports: written once, never edited.
immutable_paths = ["reports/history/**"]

[history]
max_commits = 3000

[agents]
require_claude_hooks = true
require_git_hooks = true
block_force_push = true
block_direct_push_to = []
expected_hosts = ["*.alpaca.markets", "finnhub.io", "fred.stlouisfed.org", "api.anthropic.com"]
"""
