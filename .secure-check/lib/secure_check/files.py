"""Dangerous-by-name files, and JSON/YAML blobs that are credentials by shape.

This is the check that would have caught ``upload/token.json.bak``: the
gitignore knew about ``token.json`` and nobody thought about the copy.
"""
from __future__ import annotations

import json
import re

from .findings import Finding
from .policy import Policy
from .util import looks_like_placeholder, path_matches, shannon_entropy

CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".rb", ".php",
            ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".m", ".scala", ".sh", ".md", ".rst",
            ".html", ".css", ".scss", ".less", ".styl", ".sql", ".proto", ".toml", ".ini", ".cfg",
            ".vue", ".svelte", ".mjs", ".cjs", ".mts", ".cts", ".dart", ".ex", ".exs", ".clj"}
# filenames that contain "token" but are NOT credential caches: ML tokenizer artifacts,
# design-system token files (Style Dictionary), CSRF/anti-forgery tokens.
BENIGN_TOKEN = re.compile(r"tokeni[sz]|design[-_]?tokens|tokens?[-_]?map|added[-_]?tokens|"
                          r"special[-_]?tokens|merges?|vocab|(?:^|[-_])c?xsrf|(?:^|[-_])csrf|"
                          r"anti[-_]?forgery|(?:^|[-_])tokens(?:[-_.]|$)", re.I)
BACKUP_EXT = re.compile(r"\.(?:bak|backup|old|orig|save|swp|tmp|copy|prev|\d+)$", re.I)

# (regex on basename, severity, message). Order matters: first hit wins.
NAME_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^\.env(?:\..+)?$", re.I), "critical", "dotenv file (environment secrets)"),
    (re.compile(r"^(?:client_secret|desktop_client|web_client|installed_client)[^/]*\.json$", re.I), "critical", "Google OAuth client file"),
    (re.compile(r"^(?:service[-_]?account|sa)[^/]*\.json$", re.I), "critical", "Google Cloud service-account key"),
    (re.compile(r"^[^/]*-sa\.json$", re.I), "critical", "Google Cloud service-account key"),
    (re.compile(r"^(?:credentials?|creds?)\.(?:json|ya?ml|toml|txt|ini)$", re.I), "critical", "credentials file"),
    (re.compile(r"^(?:secrets?|api[-_]?keys?)\.(?:json|ya?ml|toml|txt|ini|env)$", re.I), "critical", "secrets file"),
    (re.compile(r"(?:^|[._-])token(?:[._-]|$)", re.I), "critical", "OAuth/API token cache"),  # refined below
    (re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)$", re.I), "critical", "SSH private key"),
    (re.compile(r"\.(?:pem|key|p12|pfx|jks|keystore|ppk|asc|gpg|kdbx)$", re.I), "critical", "key material"),
    (re.compile(r"^\.(?:netrc|pypirc|npmrc|git-credentials|boto|s3cfg|htpasswd)$", re.I), "high", "tool credential file"),
    (re.compile(r"^(?:kubeconfig|\.kube)$", re.I), "high", "Kubernetes credentials"),
    (re.compile(r"^(?:cookies?|session)\.(?:json|txt|pkl|pickle)$", re.I), "high", "session/cookie dump"),
    (re.compile(r"\.(?:sqlite|sqlite3|db)$", re.I), "medium", "database file (data, possibly credentials)"),
    (re.compile(r"\.(?:pkl|pickle)$", re.I), "medium", "pickle (opaque data; may hold tokens)"),
    (re.compile(r"^(?:dump|backup)[^/]*\.(?:sql|gz|zip|tar)$", re.I), "medium", "database/backup dump"),
]

JSON_SECRET_KEYS = {"refresh_token", "client_secret", "private_key", "access_token", "api_key",
                    "secret_key", "password", "secret", "token", "auth_token", "id_token"}


def _basename_hits(base: str) -> tuple[str, str] | None:
    # strip backup suffixes repeatedly: token.json.bak.old -> token.json
    stem = base
    for _ in range(3):
        m = BACKUP_EXT.search(stem)
        if not m:
            break
        stem = stem[: m.start()]
    was_backup = stem != base
    ext = "." + stem.rsplit(".", 1)[-1].lower() if "." in stem else ""
    for rx, sev, msg in NAME_RULES:
        if not rx.search(stem):
            continue
        if msg == "OAuth/API token cache":
            # tokenizers, design tokens, csrf tokens, and code files are not credential caches
            if ext in CODE_EXT or BENIGN_TOKEN.search(stem):
                continue
        if msg == "key material" and stem.lower().endswith(".pub"):
            continue
        if was_backup:
            msg = f"{msg} (backup copy: {base})"
        return sev, msg
    return None


def check_path(relpath: str, policy: Policy, content: bytes | None = None) -> list[Finding]:
    rel = relpath.replace("\\", "/")
    if path_matches(rel, policy.allow_files):
        return []
    out: list[Finding] = []
    base = rel.rsplit("/", 1)[-1]

    if "/.secrets/" in f"/{rel}" or rel.startswith(".secrets/"):
        out.append(Finding("dangerous_path", "critical", rel, "File inside a .secrets/ directory is tracked",
                           fix="git rm --cached it, add .secrets/ to .gitignore, rotate whatever it holds."))

    for rx in policy.extra_dangerous_files:
        if re.search(rx, rel):
            out.append(Finding("dangerous_path", "high", rel, f"Matches policy extra_dangerous rule: {rx}",
                               fix="Remove from git and add an ignore rule."))
            break

    hit = _basename_hits(base)
    if hit:
        sev, msg = hit
        out.append(Finding("dangerous_filename", sev, rel, f"Tracked file looks like a credential by name: {msg}",
                           fix="git rm --cached the file, add an ignore rule that also covers backup copies, "
                               "rotate the credential if it was ever pushed, then purge history."))

    if content is not None and base.lower().endswith((".json", ".yaml", ".yml")) and len(content) < 2_000_000:
        hot = sorted(_json_secret_hits(content))
        if hot:
            out.append(Finding("credential_shaped_json", "critical", rel,
                               f"JSON/YAML with a credential field holding a secret-looking value: {', '.join(hot)}",
                               fix="This is a credential blob regardless of its name. Remove, ignore, rotate, purge."))
    return out


def _value_looks_secret(v: str) -> bool:
    """A credential value: opaque, no spaces, decent entropy, not a placeholder or a sentence."""
    v = v.strip()
    if len(v) < 12 or len(v) > 4096 or " " in v or "\n" in v:
        return False
    if v.startswith(("$", "{", "<", "http://", "https://", "/", "./", "~", "env:", "vault:")):
        return False
    if looks_like_placeholder(v):
        return False
    return shannon_entropy(v) >= 3.2


def _json_secret_hits(content: bytes) -> set[str]:
    """Credential-named keys whose VALUE looks like a real secret."""
    try:
        obj = json.loads(content.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        hits: set[str] = set()
        text = content.decode("utf-8", "replace")
        for m in re.finditer(r'^\s*["\']?([A-Za-z_][A-Za-z0-9_.\-]*)["\']?\s*:\s*["\']?([^"\'\n#]{8,})', text, re.M):
            if m.group(1).lower() in JSON_SECRET_KEYS and _value_looks_secret(m.group(2)):
                hits.add(m.group(1).lower())
        return hits
    hits = set()

    def walk(o, depth=0):
        if depth > 6:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                if str(k).lower() in JSON_SECRET_KEYS and isinstance(v, str) and _value_looks_secret(v):
                    hits.add(str(k).lower())
                walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o[:50]:
                walk(v, depth + 1)
    walk(obj)
    return hits
