"""Secret signatures.

Two families:

* **Bare tokens** -- the value has a recognisable shape on its own
  (``ya29.``, ``GOCSPX-``, ``AIza``, ``sk-ant-``, ``ghp_`` ...). Matched anywhere.
* **Contextual assignments** -- the value is opaque but the *name* next to it
  gives it away (``ALPACA_SECRET_KEY=...``, ``"refresh_token": "..."``). These
  carry an entropy floor so ``PASSWORD="password"`` does not fire.

Every pattern names the capture group holding the secret so the report can
fingerprint it without ever printing it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# --- remediation text, keyed so several patterns can share one --------------
FIX = {
    "google_oauth": (
        "Revoke the grant: https://myaccount.google.com/permissions (remove the app), then "
        "rotate the client secret in Google Cloud Console -> APIs & Services -> Credentials "
        "(create a new secret, delete the old one), re-run the device login, and purge the "
        "file from git history."
    ),
    "google_api_key": (
        "Google Cloud Console -> APIs & Services -> Credentials: regenerate or delete the key, "
        "then restrict the new one (API restrictions + application restrictions) and set a "
        "billing budget with alerts."
    ),
    "gcp_sa": (
        "Google Cloud Console -> IAM & Admin -> Service Accounts -> Keys: delete this key id, "
        "create a new key ONLY if needed, and give the account the minimum role. Check "
        "Billing -> Reports for unexpected usage."
    ),
    "anthropic": (
        "https://platform.claude.com -> Settings -> API keys: delete the key, create a new one "
        "scoped to a single workspace, and set a monthly spend limit on that workspace."
    ),
    "openai": "https://platform.openai.com/api-keys: revoke the key and set a usage limit.",
    "github": (
        "https://github.com/settings/tokens: revoke it. Check the account's security log for "
        "use you did not make. Prefer fine-grained tokens with one repo and short expiry."
    ),
    "aws": "AWS IAM -> Users -> Security credentials: deactivate then delete the key; check CloudTrail.",
    "slack": "Slack -> Apps -> your app -> revoke the token / regenerate the webhook.",
    "alpaca": (
        "https://app.alpaca.markets -> API Keys: regenerate. Keep using PAPER keys only; "
        "a live-trading key here would let anyone place real orders."
    ),
    "generic": "Rotate the credential at its provider, then purge it from git history.",
    "private_key": "Treat the key as compromised: generate a new pair, revoke the old public key everywhere.",
    "database": "Change the database password and rotate any connection string that embeds it.",
    "stripe": "https://dashboard.stripe.com/apikeys: roll the key immediately.",
    "jwt": "If this is a live session or service token, invalidate it server-side.",
}


@dataclass(frozen=True)
class Pattern:
    id: str
    severity: str
    description: str
    regex: re.Pattern[str]
    group: int = 0            # capture group holding the secret value
    min_entropy: float = 0.0  # 0 = no entropy floor (shape alone is proof)
    fix: str = FIX["generic"]
    tags: tuple[str, ...] = ()


def _p(id, severity, description, rx, *, group=0, min_entropy=0.0, fix="generic", tags=(), flags=0):
    return Pattern(id, severity, description, re.compile(rx, flags), group, min_entropy, FIX[fix], tags)


PATTERNS: list[Pattern] = [
    # ---- Google (the YouTube / Gemini / Vertex / GCS estate) ----------------
    _p("google_oauth_access_token", "critical", "Google OAuth access token",
       r"ya29\.[0-9A-Za-z_\-]{30,}", fix="google_oauth", tags=("google", "youtube")),
    _p("google_oauth_refresh_token", "critical", "Google OAuth refresh token",
       r"(?<![0-9A-Za-z_\-/])1//0[0-9A-Za-z_\-]{30,}", fix="google_oauth", tags=("google", "youtube")),
    _p("google_oauth_client_secret", "critical", "Google OAuth client secret",
       r"GOCSPX-[0-9A-Za-z_\-]{20,}", fix="google_oauth", tags=("google", "youtube")),
    _p("google_api_key", "critical", "Google API key (Gemini, TTS, Maps, ...)",
       r"AIza[0-9A-Za-z_\-]{35}", fix="google_api_key", tags=("google", "billing")),
    _p("google_oauth_client_id", "low", "Google OAuth client id (identifies your Cloud project; pair with a secret and it matters)",
       r"\b[0-9]{9,14}-[0-9a-z]{20,40}\.apps\.googleusercontent\.com\b", tags=("google",)),
    _p("gcp_service_account_key", "critical", "Google Cloud service-account key (JSON)",
       r'"type"\s*:\s*"service_account"', fix="gcp_sa", tags=("google", "billing")),
    _p("gcp_service_account_private_key_id", "critical", "Google Cloud service-account private_key_id",
       r'"private_key_id"\s*:\s*"([0-9a-f]{40})"', group=1, fix="gcp_sa", tags=("google", "billing")),

    # ---- Generic JSON credential fields (catches renamed token files) -------
    _p("json_refresh_token", "critical", "refresh_token field in a JSON/YAML blob",
       r'["\']?refresh_token["\']?\s*[:=]\s*["\']([^"\'\s]{20,})["\']', group=1, min_entropy=3.0,
       fix="google_oauth", tags=("oauth",)),
    _p("json_client_secret", "critical", "client_secret field in a JSON/YAML blob",
       r'["\']?client_secret["\']?\s*[:=]\s*["\']([^"\'\s]{10,})["\']', group=1, min_entropy=3.0,
       fix="google_oauth", tags=("oauth",)),
    _p("json_access_token", "high", "access_token field in a JSON/YAML blob",
       r'["\']?access_token["\']?\s*[:=]\s*["\']([^"\'\s]{20,})["\']', group=1, min_entropy=3.0,
       tags=("oauth",)),

    # ---- Key material --------------------------------------------------------
    _p("private_key_block", "critical", "Private key material (PEM)",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
       fix="private_key", tags=("key",)),
    _p("putty_private_key", "critical", "PuTTY private key", r"PuTTY-User-Key-File-\d", fix="private_key"),

    # ---- LLM providers -------------------------------------------------------
    _p("anthropic_api_key", "critical", "Anthropic API key",
       r"sk-ant-[A-Za-z0-9_\-]{20,}", fix="anthropic", tags=("billing",)),
    _p("openai_api_key", "critical", "OpenAI API key",
       r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}", fix="openai", tags=("billing",)),
    _p("huggingface_token", "high", "Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}\b"),

    # ---- Source control / package registries ---------------------------------
    _p("github_token", "critical", "GitHub token",
       r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})", fix="github", tags=("github",)),
    _p("gitlab_token", "critical", "GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    _p("npm_token", "high", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("pypi_token", "high", "PyPI API token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),

    # ---- Cloud ---------------------------------------------------------------
    _p("aws_access_key_id", "critical", "AWS access key id",
       r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", fix="aws", tags=("aws", "billing")),
    _p("aws_secret_access_key", "high", "AWS secret access key (contextual)",
       r"(?i)aws[^\n]{0,30}?(?:secret|key)[^\n]{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]",
       group=1, min_entropy=3.5, fix="aws", tags=("aws", "billing")),
    _p("azure_storage_key", "high", "Azure storage account key (contextual)",
       r"(?i)AccountKey=([A-Za-z0-9+/=]{80,})", group=1),

    # ---- Messaging / webhooks ------------------------------------------------
    _p("slack_token", "critical", "Slack token", r"\bxox[abprs]-[0-9A-Za-z\-]{10,}", fix="slack"),
    _p("slack_webhook", "high", "Slack incoming webhook",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", fix="slack"),
    _p("discord_webhook", "high", "Discord webhook",
       r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
    _p("telegram_bot_token", "high", "Telegram bot token", r"\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b"),
    _p("sendgrid_api_key", "critical", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    _p("twilio_api_key", "medium", "Twilio API key", r"\bSK[0-9a-fA-F]{32}\b"),

    # ---- Payments ------------------------------------------------------------
    _p("stripe_live_key", "critical", "Stripe live secret key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}", fix="stripe"),
    _p("stripe_test_key", "low", "Stripe test key", r"\b(?:sk|rk)_test_[0-9A-Za-z]{24,}", fix="stripe"),

    # ---- Tokens / URLs -------------------------------------------------------
    _p("jwt", "high", "JSON Web Token",
       r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", fix="jwt"),
    _p("database_url_with_password", "high", "Database/queue URL that embeds a password",
       r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql)://[^\s:/@'\"]+:([^\s@/'\"]{3,})@",
       group=1, fix="database"),
    _p("url_basic_auth", "medium", "URL with embedded username:password",
       r"\bhttps?://[^\s:/@'\"]+:([^\s@/'\"]{3,})@[^\s'\"]+", group=1, fix="database"),

    # ---- Provider-specific assignments used by the owner's projects ----------
    _p("alpaca_key", "critical", "Alpaca API key / secret assignment",
       r"(?i)\bALPACA_(?:API_KEY|SECRET_KEY|API_SECRET|KEY_ID)\b\s*[:=]\s*['\"]?([A-Za-z0-9]{16,})",
       group=1, min_entropy=3.0, fix="alpaca", tags=("trading",)),
    _p("finnhub_key", "high", "Finnhub API key assignment",
       r"(?i)\bFINNHUB_API_KEY\b\s*[:=]\s*['\"]?([A-Za-z0-9]{16,})", group=1, min_entropy=3.0),
    _p("stock_api_key", "high", "Market-data API key assignment (Alpha Vantage, Polygon, FRED, ...)",
       r"(?i)\b(?:ALPHA_?VANTAGE|POLYGON|FRED|TIINGO|TWELVE_?DATA)_API_KEY\b\s*[:=]\s*['\"]?([A-Za-z0-9\-]{12,})",
       group=1, min_entropy=3.0),
    _p("media_api_key", "high", "Pexels / Pixabay / vidIQ API key assignment",
       r"(?i)\b(?:PEXELS|PIXABAY|VIDIQ)_API_KEY\b\s*[:=]\s*['\"]?([A-Za-z0-9\-]{16,})",
       group=1, min_entropy=3.0),
    _p("youtube_client_secret_assignment", "critical", "YouTube / Google OAuth client secret assignment",
       r"(?i)\b(?:YOUTUBE|GOOGLE|GCP)_CLIENT_SECRET\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
       group=1, min_entropy=3.0, fix="google_oauth", tags=("google", "youtube")),
    _p("gemini_key_assignment", "critical", "Gemini / Google TTS key assignment",
       r"(?i)\b(?:GEMINI|GOOGLE_TTS|GOOGLE|VERTEX)_API_KEY\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})",
       group=1, min_entropy=3.0, fix="google_api_key", tags=("google", "billing")),
    _p("anthropic_key_assignment", "critical", "Anthropic key assignment",
       r"(?i)\b[A-Z0-9_]*ANTHROPIC_API_KEY\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})",
       group=1, min_entropy=3.0, fix="anthropic", tags=("billing",)),

    # ---- Last resort: something named like a secret with a random-looking value
    _p("generic_secret_assignment", "medium", "Secret-looking assignment (name says secret, value looks random)",
       r"(?i)\b(?:api[_\-]?key|apikey|secret[_\-]?key|client[_\-]?secret|access[_\-]?token|auth[_\-]?token|"
       r"refresh[_\-]?token|private[_\-]?key|password|passwd|pwd|secret|token|api[_\-]?secret|bearer)\b"
       r"\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]",
       group=1, min_entropy=3.5),
]

BY_ID = {p.id: p for p in PATTERNS}
