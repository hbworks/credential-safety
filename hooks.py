"""Hook implementations for credential safety."""
import os
import re
import logging

try:
    from . import patterns
except (ImportError, ValueError):
    import patterns

logger = logging.getLogger(__name__)


# Patterns for natural language & contextual credential references
_NATURAL_LANGUAGE_PATTERNS = [
    # English patterns
    r"(?i)(?<![a-zA-Z0-9_])(password|token|api[\s_-]?key|secret|auth)(?![a-zA-Z0-9_])(?:\s+(?:is|was|used|changed|set|updated|generated|configured))*(?:\s*(?:is|was|to|for|as|into|:|:=|=|：))+\s*['\"]?([^\s'\"!.,;:\\|{}()\[\]<>&#]+)['\"]?(?:\s|\.|$|,|!|。|;)",

    # Japanese patterns (secret part must be ASCII)
    r"(パスワード|トークン|シークレット|APIキー|認証情報|認証キー)(?:\s*(?:は|を|に|へ|で|：|:|=|として))+\s*['\"]?([a-zA-Z0-9_\-.~!@#$%^&*+/=]{8,})['\"]?",
]

# Compiled once; the offline scanner reuses this tuple instead of its own copy.
_NL_COMPILED = tuple(re.compile(p) for p in _NATURAL_LANGUAGE_PATTERNS)



# Common key names for KEY=VALUE / KEY: VALUE redaction
# Matches keys like SECRET_KEY, CLIENT_SECRET, AUTH_TOKEN, ACCESS_KEY, DATABASE_URL, etc.
_SECRET_KEY_REGEX = (
    r"(?:[a-zA-Z0-9_-]*(?:api[_-]?key|password|passwd|token|secret|auth|private_key|database_url|db_pass)[a-zA-Z0-9_-]*"
    r"|access[_-]?key|signing[_-]?key|encryption[_-]?key|bearer[_-]?token|client[_-]?secret|app[_-]?secret)"
)



# Precompiled patterns for the hook passes. Compiling once at import avoids rebuilding an
# f-string pattern on every tool call and removes reliance on re's internal 512-entry cache.
_WS = r"[^\S\r\n]*"
_LN = rf"(?:[0-9]{{1,7}}[|:]{_WS})?"
_RE_KV_TOOL = re.compile(rf"({_SECRET_KEY_REGEX})\s*=\s*([^\s\n\\\"'&;]+)", re.IGNORECASE)
# Quoted assignments (`API_KEY="sk-…"`), kept separate so the unquoted rule above can stop
# at a quote and never eat the delimiter that closes a surrounding JSON/YAML string.
_RE_KV_TOOL_QUOTED = re.compile(rf"({_SECRET_KEY_REGEX})\s*=\s*([\"'])([^\"'\n\\]+)\2", re.IGNORECASE)
_RE_KV_ANY = re.compile(rf"({_SECRET_KEY_REGEX})\s*=\s*([^\s\n\\\"']+)", re.IGNORECASE)
_RE_ENV_KV = re.compile(
    r"([A-Z_0-9]*(?:password|token|api[_-]?key|secret|auth)[A-Z_0-9]*)\s*=\s*([^\s\n\\\"']+)",
    re.IGNORECASE,
)
_RE_JSON = re.compile(rf'("({_SECRET_KEY_REGEX})"\s*:\s*)"([^"]+)"', re.IGNORECASE)
_RE_YAML_EOL = re.compile(
    rf'(?m)^({_WS}{_LN}({_SECRET_KEY_REGEX}){_WS}:[^\S\r\n]+)["\']?([^"\'\r\n]+?)["\']?\s*$',
    re.IGNORECASE,
)
_RE_YAML_LINE = re.compile(
    rf'(?m)^({_WS}{_LN}({_SECRET_KEY_REGEX}){_WS}:[^\S\r\n]+)["\']?([^"\'\r\n]+?)["\']?[^\S\r\n]*$',
    re.IGNORECASE,
)
_RE_ESC_JSON = re.compile(
    rf'(\\"({_SECRET_KEY_REGEX})\\"{_WS}:{_WS})\\"((?:[^"\\]|\\.)*)\\"', re.IGNORECASE
)
_RE_ESC_YAML = re.compile(
    rf'((?:\\n){_WS}(?:[0-9]{{1,7}}\|{_WS})?({_SECRET_KEY_REGEX}){_WS}:{_WS})([^\\\s"\']+)',
    re.IGNORECASE,
)

PLACEHOLDER_PREFIXES = (
    "your-", "your_", "my-", "my_", "example-", "example_", "sample-", "sample_",
    "test-", "test_", "dummy-", "dummy_", "insert-", "insert_", "replace-", "replace_",
    "enter-", "enter_", "set-", "set_", "change-me", "changeme", "todo-", "todo_",
    "<your", "<api", "<token", "<secret", "<password"
)

PLACEHOLDER_KEYWORDS = {
    "changed", "hidden", "required", "optional", "example", "default", "secret", "string",
    "undefined", "none", "null", "true", "false", "password", "bearer", "token", "apikey",
    "value", "content", "config", "status", "created", "updated", "deleted", "masked",
    "redacted", "placeholder", "dummy", "sample", "test", "admin", "user", "guest",
    "your-api-key", "your-admin-api-key", "your_api_key", "api_key_here", "your_token_here",
    "your-token", "your_secret", "your-secret", "your-password", "your_password"
}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    import math
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((count / len(s)) * math.log2(count / len(s)) for count in freq.values())


def _is_placeholder(value: str) -> bool:
    """Check if value is a documentation placeholder, dummy value, or already masked."""
    if not value:
        return True
    val_clean = value.strip("\"'`<>[]{}")
    val_lower = val_clean.lower()

    # 1. Reject already masked / truncated values (e.g. 'sk-123...456', '***', '...')
    if "..." in val_clean or "***" in val_clean:
        return True
    # Angle-bracket placeholders only (`<your-token>`, `<API_KEY>`): a bare '>' is a code
    # operator, and `x->y12345` is a real password.
    if re.fullmatch(r"<[\w :_.\-]+>", val_clean) or re.search(r"<[A-Za-z_][\w \-]*>", val_clean):
        return True

    # 2. Exact match ignored / placeholder words
    if val_lower in PLACEHOLDER_KEYWORDS:
        return True

    # 3. Starts with placeholder prefix (e.g. 'your-admin-key', 'example_token')
    if any(val_lower.startswith(p) for p in PLACEHOLDER_PREFIXES):
        return True

    # 4. Trailing '_here', '-here', '_key', '-key' without digits
    if val_lower.endswith(("_here", "-here", "_key", "-key", "_token", "-token", "_secret", "-secret")) and not re.search(r"[0-9]", val_clean):
        return True

    return False


def _looks_like_secret(value: str) -> bool:
    """Accurate heuristic: detect genuine credentials and reject placeholders, code & words."""
    if not value or len(value) < 8:
        return False

    # Real credentials (API keys, hashes, tokens, passwords) are strictly ASCII
    if not value.isascii():
        return False

    val_clean = value.strip("\"'`<>[]{}")
    val_lower = val_clean.lower()

    if _is_placeholder(value):
        return False

    # Reject code syntax & expressions (e.g. array indexing samples[0], func(x), obj.prop)
    # Notice: '+' and '=' are intentionally permitted for Base64 encoded secrets / padding
    if any(c in val_clean for c in "[](){};,\\"):
        return False

    # '=' is strictly checked: valid only as trailing Base64 padding (at most 2 '=' at the end)
    # Rejects code assignments or equations like 'a=b' or 'x==y'
    if "=" in val_clean:
        padding_stripped = val_clean.rstrip("=")
        num_eq = len(val_clean) - len(padding_stripped)
        if num_eq > 2 or "=" in padding_stripped:
            return False

    # '+' cannot appear at the start (e.g. '+1234' phone/offset) or with whitespace
    if val_clean.startswith("+") or " " in val_clean:
        return False

    # Known real credential prefixes (override heuristics)
    if any(val_clean.startswith(p) for p in (
        "AKIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
        "AIza", "ya29.", "hf_", "SG.", "xox", "xapp-", "sk_live_", "rk_live_", "sk_test_", "rk_test_"
    )):
        return True

    # Twilio SID / API Key (34 chars starting with AC / SK followed by hex)
    if (val_clean.startswith("AC") or val_clean.startswith("SK")) and len(val_clean) == 34 and re.fullmatch(r"[A-Za-z0-9]+", val_clean):
        return True

    if val_clean.startswith("sk-"):
        # Reject machine learning libraries (sk-learn, sk-image, etc.) or pure word sequences without digits
        if any(val_lower.startswith(p) for p in ("sk-learn", "sk-image", "sk-time", "sk-spatial", "sk-opt", "sk-video")):
            return False
        if not re.search(r"[0-9]", val_clean) or len(val_clean) < 20:
            return False
        return True

    # 6. Hex strings (20+ hex characters, e.g. md5/sha or raw hex tokens)
    if len(val_clean) >= 20 and re.fullmatch(r"[0-9a-fA-F]+", val_clean):
        return True

    # 7. Character class analysis
    has_lower = bool(re.search(r"[a-z]", val_clean))
    has_upper = bool(re.search(r"[A-Z]", val_clean))
    has_digit = bool(re.search(r"[0-9]", val_clean))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", val_clean))

    # Reject if it contains ONLY letters and dashes/underscores with NO digits (kebab-case / snake_case placeholder)
    if (has_lower or has_upper) and not has_digit:
        other_specials = re.sub(r"[a-zA-Z\-_]", "", val_clean)
        if not other_specials:
            # A kebab/snake placeholder is a word; a long mixed-case run with high entropy
            # is a random alphabetic token (`AbCdEfGhIjKlMnOpQrStUvWx`) and must mask.
            if has_lower and has_upper and len(val_clean) >= 20 and _shannon_entropy(val_clean) >= 3.5:
                return True
            return False

    class_count = sum([has_lower, has_upper, has_digit, has_special])

    # 8. Base64 encoded tokens / keys (e.g. standard cryptographic hashes, HMAC keys, bearer tokens)
    # Character set: A-Z, a-z, 0-9, +, /, with 0-2 trailing '=' padding
    if len(val_clean) >= 12 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", val_clean):
        if (has_digit or (has_lower and has_upper) or has_special) and _shannon_entropy(val_clean) >= 2.6:
            return True

    # 3+ character classes with high entropy (e.g. Lower+Upper+Digit or Lower+Digit+Special)
    if class_count >= 3 and len(val_clean) >= 8:
        if _shannon_entropy(val_clean) >= 2.8:
            return True

    # 2 classes with digits and high entropy (12+ chars)
    if has_digit and class_count >= 2 and len(val_clean) >= 12:
        if _shannon_entropy(val_clean) >= 3.0:
            return True

    return False


_SENSITIVE_KEY_SUBSTRINGS = (
    "password", "passwd", "token", "secret", "api_key", "apikey", "auth_key",
    "private_key", "db_pass", "database_url", "credential", "access_key", "bearer",
    "パスワード", "トークン", "シークレット", "apiキー", "認証情報", "認証キー"
)


def _is_sensitive_key(key_name: str) -> bool:
    """Check if key name strongly indicates a sensitive secret or password."""
    if not key_name:
        return False
    k = key_name.lower().replace("-", "_")
    return any(sub in k for sub in _SENSITIVE_KEY_SUBSTRINGS)


# ---------------------------------------------------------------------------
# Code-shaped values
#
# Tool results frequently carry source code read from a file: `password: user.password`,
# `token = get_token()`, `api_key = os.environ.get("X")`. Those are references, not
# credentials, and masking them corrupts the code the model is trying to read. The
# key-context fallback in _should_mask_value must skip anything that reads as an
# expression, an attribute reference, a template, or a version/path literal.
# ---------------------------------------------------------------------------
_CODE_CALL_RE = re.compile(r"[A-Za-z_$][\w$.]*\s*\(")
_CODE_ATTR_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$")
# Tokens that cannot appear in a literal credential but are ubiquitous in code.
# '=', '==' and '!=' are deliberately absent: base64 padding ends in '=='. Braces and
# operators ('{', '->', '::', '&&', ':=') are absent too — `P@ss{word}123` and `x->y12345`
# are real passwords, so a value is only code here when it is a call/annotation/bracket shape.
_CODE_STRUCT_TOKENS = ("[", "]")
_TEMPLATE_RE = re.compile(r"^(?:[rbuf]{1,2})?['\"]?\{[\w.$\[\]]+\}['\"]?$")
# `$DB_PASSWORD`, `${DB_PASSWORD}`, `$(cat key)` — but not the '$' inside `pa$$word123`.
_SHELL_VAR_RE = re.compile(r"(?<![$\w])\$(?:\{[^}]*\}|[A-Za-z_][\w]*|\([^)]*\))")
_URL_RE = re.compile(r"^[A-Za-z][\w+.-]*://")
_URL_QUERY_RE = re.compile(r"[?&]([^=&#\s]+)=([^&#\s]+)")
# Credentials *inside* a URL: userinfo (`scheme://user:pw@host`) and sensitive query
# parameters (`?token=…`). The value character classes stop at quotes/delimiters so a
# surrounding JSON/YAML string stays well-formed.
_URL_USERINFO_RE = re.compile(r"([A-Za-z][\w+.-]*://)([^\s/\"'<>@]+@)")
# The value class is URL-safe token characters only, so prose/backticked examples
# (`?token=…`) never match.
_URL_CRED_PARAM_RE = re.compile(r"([?&][^=&#\s\"'<>]+)=([A-Za-z0-9._~%+/-]{4,})")
# Opaque token in a URL path (`/reset/a1B2c3D4…`). Mixed case + digits + high entropy only,
# so UUIDs and lowercase hex digests in paths are left alone.
# An opaque path segment ends at a path/query/fragment delimiter, whitespace, or the
# punctuation that follows a URL in prose/markdown (`…/token.` or `[x](…/token)`).
_URL_PATH_SEG_RE = re.compile(r"/([A-Za-z0-9_\-]{16,})(?=[/?#\"'\s.,;:!)\]]|$)")
_URL_TOKEN_MIN_LEN = 16
_URL_TOKEN_MIN_ENTROPY = 3.5
_URL_TOKEN_MIN_UPPER_RATIO = 0.25
# A URL span. Everything below is applied *inside* a matched span only, so a plain
# filesystem path (`/srv/app/releases/<id>/main.py`) is never rewritten.
_URL_SPAN_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>`]+")
# Version literals (semver, dotted builds) and versioned paths:
# `v1.2.3`, `2.3.1-beta.1`, `node/18.17.0/bin/node`, `/usr/local/lib/tokens.d/1.2.3`.
_SEMVER_RE = re.compile(r"^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.\-]+)?$")
_PATH_LIKE_RE = re.compile(r"^[\w.@+~%:/-]+$")
_DOTTED_VERSION_RE = re.compile(r"(?:^|/)v?\d+(?:\.\d+)+")


def _url_carries_credentials(v: str) -> bool:
    """True when a URL embeds a secret: userinfo, or a sensitive query parameter."""
    if "@" in v.split("?", 1)[0]:
        return True
    for match in _URL_QUERY_RE.finditer(v):
        name, val = match.group(1), match.group(2)
        if _is_credential_name(name) and (len(val) >= 4 or _looks_like_secret(val)):
            return True
    return False


def _looks_like_structural_value(value: str) -> bool:
    """Version literals, versioned paths and credential-free URLs: high entropy, not secrets.

    Checked *before* the entropy heuristic because these shapes score above the threshold.
    A URL that embeds userinfo or a sensitive query parameter is deliberately excluded here
    so it still reaches the redaction paths.
    """
    v = value.strip().strip("\"'`")
    if not v:
        return False
    if _SEMVER_RE.match(v):
        return True
    if _URL_RE.match(v):
        return not _url_carries_credentials(v)
    return bool(
        _PATH_LIKE_RE.match(v)
        and "/" in v
        and (_DOTTED_VERSION_RE.search(v) or re.search(r"\.[A-Za-z]{1,8}$", v))
    )


def _looks_like_code_expr(value: str) -> bool:
    """True when a value is a code reference / expression, not a literal secret.

    Runs *after* the entropy heuristic, so a password that merely resembles code syntax
    (`P@ss{word}123`, `x->y12345`) has already been claimed by `_looks_like_secret`.
    Excludes '+' alone and digit-only forms so 'admin123' and E.164 ('+819012345678')
    stay maskable, and requires an attribute chain to be digit-free so 'My.P4ssw0rd' masks.
    """
    if not value:
        return False
    raw = value.strip()
    v = raw.strip("\"'`")
    if not v:
        return False
    if _looks_like_structural_value(v):
        return True
    if any(tok in v for tok in _CODE_STRUCT_TOKENS):
        return True
    # A bare template keeps its closing brace only in the raw form (`f"{pw}"` → `f"{pw`).
    if _TEMPLATE_RE.match(raw) or _TEMPLATE_RE.match(v):
        return True
    if _SHELL_VAR_RE.search(v):
        return True
    if not re.search(r"\d", v) and _CODE_ATTR_RE.match(v):
        return True
    return bool(_CODE_CALL_RE.search(v))


# Names that *contain* a sensitive substring but denote metadata, not a credential:
# `token_id`, `token_type`, `secret_name`, `api_key_endpoint`. Kept narrow on purpose —
# a genuine token stored under such a name is still caught by the entropy heuristic.
_METADATA_NAME_SUFFIXES = (
    "_id", "_ids", "_type", "_name", "_count", "_length", "_len", "_size", "_expires",
    "_expires_at", "_expiry", "_ttl", "_format", "_alg", "_algorithm", "_version",
    "_url", "_uri", "_endpoint", "_path", "_mode", "_enabled", "_label", "_hint",
    "_placeholder", "_required",
)


def _is_credential_name(key_name: str) -> bool:
    """True when a key/parameter name denotes a credential itself, not metadata about one."""
    if not key_name or not _is_sensitive_key(key_name):
        return False
    k = key_name.lower().replace("-", "_").lstrip("?&")
    return not k.endswith(_METADATA_NAME_SUFFIXES)


def _should_mask_value(key_name: str, value: str) -> bool:
    """Determine if a value should be masked, taking key context into account.

    - Rejects documentation placeholders and already masked values.
    - Accepts genuine secrets by entropy/structure heuristics (_looks_like_secret).
    - For strongly sensitive keys (e.g. password, token, secret), masks values of at least 4 characters
      even if low-entropy or short (e.g. 'admin123', 'simplepass').
    """
    if not value or not isinstance(value, str):
        return False
    clean_val = value.strip("\"'`<>[]{}")
    if not clean_val or _is_placeholder(clean_val):
        return False
    # Version literals / versioned paths / credential-free URLs score above the entropy
    # threshold but are not secrets. A URL carrying userinfo or a sensitive query param is
    # excluded from that shape and falls through to the redaction paths below.
    if _looks_like_structural_value(clean_val):
        return False
    if _looks_like_secret(clean_val):
        return True
    # Code references are not credentials: `password: user.password`, `token = get_token()`,
    # `token: Optional[str]`. Checked after the entropy heuristic so a password that merely
    # resembles code syntax (`P@ss{word}123`) is already claimed above.
    if _looks_like_code_expr(value):
        return False
    if _is_credential_name(key_name) and len(clean_val) >= 4 and clean_val.isascii():
        if clean_val.lower() in ("true", "false", "null", "none"):
            return False
        # Numeric settings under a token-ish key are configuration, not credentials:
        # `max_tokens: 32768`, `proactive_prune_min_reclaim_tokens: 4096`. Long digit-only
        # runs that look like hex/hash tokens are still caught by _looks_like_secret above.
        if clean_val.isdigit():
            return False
        return True
    return False


# Single source for the direct-signature patterns: compiled once here and shared with the
# offline scanner (`scan_credentials.PATTERNS`), so the two layers cannot drift apart.
COMPILED_PATTERNS: tuple = tuple((p, re.compile(p)) for p in patterns.PATTERNS)


def compiled_direct_patterns() -> tuple:
    """Return ``((pattern_source, compiled), ...)`` for direct-signature matching."""
    return COMPILED_PATTERNS


def _apply_direct_patterns(text: str) -> str:
    """Apply compiled regex patterns from patterns.PATTERNS."""
    result = text
    for _, pattern in COMPILED_PATTERNS:
        result = pattern.sub("***", result)
    return result


def _replace_kv_quoted(m: re.Match) -> str:
    """Mask a quoted assignment while preserving the quotes and the surrounding syntax."""
    key_name, quote, val = m.group(1), m.group(2), m.group(3)
    if _should_mask_value(key_name, val):
        return f"{key_name}={quote}***{quote}"
    return m.group(0)


def _replace_kv_if_secret(match: re.Match) -> str:
    """Replace value in KEY=val only if it looks like a secret or sensitive key."""
    key_name = match.group(1)
    val = match.group(2)
    if _should_mask_value(key_name, val):
        return f"{key_name}=***"
    return match.group(0)


def _replace_json_if_secret(match: re.Match) -> str:
    """Replace JSON value only if it looks like a secret or sensitive key."""
    key_prefix = match.group(1)
    key_name = match.group(2)
    val = match.group(3)
    if _should_mask_value(key_name, val):
        return f'{key_prefix}"***"'
    return match.group(0)


def _replace_escaped_json_if_secret(match: re.Match) -> str:
    """Replace a JSON value that arrives escaped (``\\"key\\": \\"value\\"``).

    Tool results from file_tools / code execution / subprocess wrappers are often
    ``json.dumps()``-ed, so an inner ``{"client_secret": "..."}`` reaches this hook as
    ``{\\"client_secret\\": \\"...\\"}`` and the unescaped JSON pass above never matches it.
    """
    prefix, key_name, raw = match.group(1), match.group(2), match.group(3)
    value = raw.replace('\\"', '"').replace("\\\\", "\\")
    if _should_mask_value(key_name, value):
        return prefix + '\\"***\\"'
    return match.group(0)


def _replace_escaped_yaml_if_secret(match: re.Match) -> str:
    """Replace a YAML/colon value that arrives inside an escaped (``\\n``-joined) payload."""
    prefix, key_name, value = match.group(1), match.group(2), match.group(3)
    if _should_mask_value(key_name, value):
        return prefix + "***"
    return match.group(0)


def _nl_candidate_is_secret(value: str) -> bool:
    """Gate for natural-language matches: a bare word ('expired', 'amazing') is not a secret."""
    if not value:
        return False
    if _looks_like_secret(value):
        return True
    return len(value) >= 6 and any(ch.isdigit() for ch in value)


def _apply_natural_language(text: str) -> str:
    """Redact 'the API key is X' / 'APIキーは X です' mentions in tool results and logs."""
    def _repl(match: re.Match) -> str:
        if len(match.groups()) >= 2:
            candidate = match.group(2)
            if candidate != "***" and _nl_candidate_is_secret(candidate):
                return match.group(0).replace(candidate, "***", 1)
        return match.group(0)

    for pattern in _NL_COMPILED:
        text = pattern.sub(_repl, text)
    return text


# ---------------------------------------------------------------------------
# Code-file reads
#
# `read_file` / `search_files` on a source file return code, not configuration. The
# YAML/colon pass treats `key: value` as config and the natural-language pass treats
# `# the token is …` as prose; on a source file both mangle the code the model needs to
# read and can trip `_looks_like_code_expr` only after the damage. So for code
# extensions those two passes are skipped here. Direct signature patterns and
# quoted-literal assignments still apply, and the offline scanner is unaffected.
# ---------------------------------------------------------------------------
_CODE_TOOL_NAMES = frozenset({"read_file", "read_multiple_files", "search_files"})
_CODE_EXTENSIONS = frozenset({
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs",
    ".java", ".kt", ".kts", ".scala", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
    ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".lua", ".pl", ".pm", ".r", ".jl",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".dart", ".ex", ".exs", ".erl",
    ".hs", ".clj", ".groovy", ".sql", ".vue", ".svelte", ".zig", ".nim", ".cr",
})
_CODE_FILENAME_RE = re.compile(
    r"[\w./~+-]+\.(?:" + "|".join(sorted(e.lstrip(".") for e in _CODE_EXTENSIONS)) + r")\b",
    re.IGNORECASE,
)
_PATH_KWARGS = ("path", "file_path", "filepath", "paths", "files", "filename", "file", "target")
_QUOTED_RE = re.compile(r"^(['\"]).*\1$")


def _is_literal_or_secret(raw: str) -> bool:
    """A quoted literal or an independently secret-looking value.

    Used for `key: value` inside a source file, where an unquoted value is a reference
    (`user.password`) or a type annotation (`Optional[str]`) and a quoted one is data.
    """
    s = raw.strip()
    return bool(_QUOTED_RE.match(s)) or _looks_like_secret(s.strip("\"'"))


def _iter_target_paths(kwargs: dict):
    """Yield every path-like value the caller passed, including nested ``args`` dict."""
    sources = [kwargs]
    args = kwargs.get("args")
    if isinstance(args, dict):
        sources.append(args)
    for source in sources:
        for key in _PATH_KWARGS:
            raw = source.get(key)
            if isinstance(raw, str):
                yield raw
            elif isinstance(raw, (list, tuple, set)):
                for item in raw:
                    if isinstance(item, str):
                        yield item


def _is_code_file_read(tool_name: str, result: str, kwargs: dict) -> bool:
    """True when this tool result is the contents of a source file."""
    if tool_name not in _CODE_TOOL_NAMES:
        return False
    for path in _iter_target_paths(kwargs):
        if os.path.splitext(path.rstrip("/"))[1].lower() in _CODE_EXTENSIONS:
            return True
    # No usable path argument (e.g. a caller that only passes the result): sniff the
    # payload header for a source filename before deciding.
    return bool(_CODE_FILENAME_RE.search(result[:600]))


def _mask_one_url(url: str) -> str:
    """Mask the credential parts of a single URL, leaving the rest of it readable."""
    def _userinfo(match: re.Match) -> str:
        scheme, userinfo = match.group(1), match.group(2)
        if userinfo == "***@":
            return match.group(0)
        body = userinfo[:-1]
        cred = body.split(":", 1)[1] if ":" in body else body
        # Documentation placeholders (`scheme://user:pw@host`) are not credentials.
        if len(cred) < 6 and not _looks_like_secret(cred):
            return match.group(0)
        return scheme + "***@"

    def _param(match: re.Match) -> str:
        name, val = match.group(1), match.group(2)
        if val == "***" or not _is_credential_name(name[1:]):
            return match.group(0)
        return f"{name}=***"

    def _path_segment(match: re.Match) -> str:
        seg = match.group(1)
        # A long hex run is a digest/token regardless of case: reset URLs really do carry
        # 32/40-character lowercase hex. Hyphenated UUIDs fail this and stay readable.
        if re.fullmatch(r"[0-9a-fA-F]{32,}", seg):
            return "/***"
        if not (re.search(r"[a-z]", seg) and re.search(r"[A-Z]", seg) and re.search(r"\d", seg)):
            return match.group(0)  # UUIDs, plain ids, slugs
        if len(seg) < _URL_TOKEN_MIN_LEN or _shannon_entropy(seg) < _URL_TOKEN_MIN_ENTROPY:
            return match.group(0)
        # Random tokens are roughly half uppercase in their letter run; a CamelCase slug
        # (`SummerSale2026Bundle`, 0.16) is not. Word runs are deliberately NOT used as a
        # signal: `tokenAbCdEf…` would escape. This ratio is a heuristic, not a measured
        # capture rate for real-world tokens — see README.
        letters = re.sub(r"[^A-Za-z]", "", seg)
        if not letters or sum(c.isupper() for c in letters) / len(letters) < _URL_TOKEN_MIN_UPPER_RATIO:
            return match.group(0)
        return "/***"

    url = _URL_USERINFO_RE.sub(_userinfo, url)
    url = _URL_CRED_PARAM_RE.sub(_param, url)

    scheme_end = url.find("://") + 3
    head, rest = url[:scheme_end], url[scheme_end:]
    path, sep, tail = rest.partition("?")
    path = _URL_PATH_SEG_RE.sub(_path_segment, path)
    return head + path + sep + tail


def _apply_url_credentials(text: str) -> str:
    """Mask credentials embedded *inside* a URL, wherever the URL appears.

    A URL is often attached to a key that says nothing about secrets
    (`{"redirect_url": "https://user:pw@host/cb"}`), so the key-named passes never look at
    it. Only the credential parts are masked — userinfo, a sensitive query parameter, an
    opaque token in the path — which keeps the output parseable: the quote closing a JSON
    string survives, and the host stays readable for context.

    Scoped to ``scheme://…`` spans on purpose: a bare filesystem path is not a URL and must
    not be rewritten.
    """
    return _URL_SPAN_RE.sub(lambda m: _mask_one_url(m.group(0)), text)


def redact_tool_result(tool_name: str, result: str, **kwargs) -> str | None:
    """Transform hook: redact credentials from tool results.

    Catches:
    - env var dumps (cat .env, printenv)
    - config file contents
    - JSON responses with credential fields
    - Direct matching against known secret signatures
    """
    if not isinstance(result, str):
        return None

    original = result
    code_file = _is_code_file_read(tool_name, result, kwargs)

    # 1. Apply known credential patterns
    result = _apply_direct_patterns(result)

    # 1b. Credentials embedded in a URL, whatever key it hangs off. Runs before the
    #     KEY=value pass so `?token=…` is already masked when the delimiter rule sees it.
    result = _apply_url_credentials(result)

    # 2. Redact KEY=value patterns (only genuine secrets). Quoted values go first: the
    #    unquoted rule stops at a quote and must not eat a JSON string's closing quote.
    result = _RE_KV_TOOL_QUOTED.sub(_replace_kv_quoted, result)
    result = _RE_KV_TOOL.sub(_replace_kv_if_secret, result)

    # 3. Redact JSON credential fields (preserving keys, only genuine secrets)
    result = _RE_JSON.sub(_replace_json_if_secret, result)


    # 4. Redact YAML/colon key-value fields. In a source file `key: value` is an object
    #    literal or a type annotation, so only a quoted literal or an independently
    #    secret-looking value is masked: `password: "hunter2abc"` yes, `token: Optional[str]`
    #    and `password: user.password` no.
    def _replace_yaml(m):
        prefix = m.group(1)
        key_name = m.group(2)
        val = m.group(3)
        if code_file and not _is_literal_or_secret(val):
            return m.group(0)
        if _should_mask_value(key_name, val):
            return f"{prefix}***"
        return m.group(0)

    result = _RE_YAML_EOL.sub(_replace_yaml, result)

    # 5. Escaped payloads: tool results are often json.dumps()-ed, so inner quotes arrive as \"
    result = _RE_ESC_JSON.sub(_replace_escaped_json_if_secret, result)
    result = _RE_ESC_YAML.sub(_replace_escaped_yaml_if_secret, result)

    # 6. Natural-language mentions ("api key is …", "APIキーは …"). Runs for source files
    #    too: a comment is exactly where a leaked credential gets written down.
    result = _apply_natural_language(result)

    if result != original:
        logger.debug(f"Redacted credential from tool {tool_name}")
        return result

    return None


def redact_llm_output(response_text: str, **kwargs) -> str | None:
    """Transform hook: redact credentials from LLM output (including thinking blocks & explanations).

    Catches:
    - Direct credential signatures (OpenAI, AWS, JWT, etc.)
    - Model explaining what it fixed (meta-discussion in English/Japanese)
    - Code blocks / config snippets emitted by the model
    """
    if not isinstance(response_text, str):
        return None

    original = response_text
    result = response_text

    # 1. Apply known credential patterns directly (scrubs raw tokens everywhere, including  thinking blocks)
    result = _apply_direct_patterns(result)

    # 1b. Credentials embedded in a URL (userinfo / sensitive query parameter)
    result = _apply_url_credentials(result)

    # 2. Redact KEY=value and key: value pairs in code blocks or text (only genuine secrets)
    result = _RE_KV_TOOL_QUOTED.sub(_replace_kv_quoted, result)
    result = _RE_KV_ANY.sub(_replace_kv_if_secret, result)
    result = _RE_JSON.sub(_replace_json_if_secret, result)

    # Redact YAML/colon key-value fields in LLM output
    def _replace_yaml_llm(m):
        prefix = m.group(1)
        key_name = m.group(2)
        val = m.group(3)
        if _should_mask_value(key_name, val):
            return f"{prefix}***"
        return m.group(0)

    result = _RE_YAML_EOL.sub(_replace_yaml_llm, result)

    # 3. Natural language credential references (meta-discussion)
    def _nl_replacer(m):
        if len(m.groups()) >= 2:
            key_name = m.group(1)
            potential_secret = m.group(2)
            if potential_secret != "***" and _should_mask_value(key_name, potential_secret):
                return m.group(0).replace(potential_secret, "***", 1)
        return m.group(0)

    for pattern in _NL_COMPILED:
        result = pattern.sub(_nl_replacer, result)

    if result != original:
        logger.debug("Redacted credential references from LLM output")
        return result

    return None



def redact_terminal_output(command: str | None, output: str, **kwargs) -> str | None:
    """Transform hook: redact credentials from terminal output.

    Catches:
    - Environment variable dumps (env, printenv, set, export)
    - .env file contents (cat .env, head .env, etc.)
    - Error messages with credentials
    """
    if not isinstance(output, str):
        return None

    original = output
    result = output

    # 1. Direct patterns
    result = _apply_direct_patterns(result)

    # 1b. Credentials embedded in a URL (userinfo / sensitive query parameter)
    result = _apply_url_credentials(result)

    # 2. For env dumps and .env reads, redact KEY=value (only genuine secrets to preserve placeholders)
    if command and any(x in command.lower() for x in ["env", "printenv", "export", ".env"]):
        def _replace_env_secret(m):
            key = m.group(1)
            val = m.group(2)
            if _should_mask_value(key, val):
                return f"{key}=***"
            return m.group(0)

        result = _RE_ENV_KV.sub(_replace_env_secret, result)

    # 3. General: KEY=value pattern anywhere (only genuine secrets)
    result = _RE_KV_TOOL_QUOTED.sub(_replace_kv_quoted, result)
    result = _RE_KV_ANY.sub(_replace_kv_if_secret, result)

    # 4. JSON-shaped secrets: {"client_secret": "..."} (core's terminal pass skips these)
    result = _RE_JSON.sub(_replace_json_if_secret, result)

    # 5. YAML / colon-shaped secrets: "  password: ..."
    def _replace_yaml_term(m):
        prefix = m.group(1)
        key_name = m.group(2)
        val = m.group(3)
        if _should_mask_value(key_name, val):
            return f"{prefix}***"
        return m.group(0)

    result = _RE_YAML_LINE.sub(_replace_yaml_term, result)

    # 6. Escaped payloads (a log line carrying json.dumps() output)
    result = _RE_ESC_JSON.sub(_replace_escaped_json_if_secret, result)
    result = _RE_ESC_YAML.sub(_replace_escaped_yaml_if_secret, result)

    # 7. Natural-language mentions ("api key is …", "パスワードは … です")
    result = _apply_natural_language(result)

    if result != original:
        return result

    return None