# .secure-check

Vendored copy of [secure-check](https://github.com/Danish99011/Secure-check): the guard that stops
credentials from being committed, watches the files that must not change silently, and gives the
AI agents in this repository a security gate they cannot argue with.

* `lib/secure_check/` — the tool (Python 3.11+, standard library only). Re-run
  `secure-check init` from the Secure-check repository to update it.
* `hooks/` — git hooks; `install-hooks` copies them into `.git/hooks` (the Claude Code
  SessionStart hook does this on every fresh container).
* `baseline.json` — sha256 of every protected file, as approved by the owner. Regenerate with
  `secure-check baseline` only when the owner approved the change.

Policy lives in `../.secure-check.toml`. Run `python3 -m secure_check --help` with
`PYTHONPATH=.secure-check/lib`.
