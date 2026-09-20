"""secure-check: a safety wall for repositories that AI agents commit to.

Standard library only (Python 3.11+). Design rules:

* A finding never carries the secret itself -- only a redacted preview and a
  sha256 fingerprint, so the report can be pasted anywhere.
* Every check is deterministic. The LLM "guard agent" reads this tool's
  verdict; it does not replace it.
* Exit codes: 0 clean, 1 findings at or above the fail threshold, 2 tool error.
"""

__version__ = "0.2.0"
