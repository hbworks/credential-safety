"""Hook implementations for credential safety."""
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
    r"(?i)(?<![a-zA-Z0-9_])(password|token|api[_-]?key|secret|auth)(?![a-zA-Z0-9_])(?:\s+(?:is|was|used|changed|set|updated|generated|configured))*(?:\s*(?:is|was|to|for|as|into|:|:=|=|：))+\s*['\"]?([^\s'\"!.,;:]+)['\"]?(?:\s|\.|$|,|!|。|;)",

    # Japanese patterns (secret part must be ASCII)
    r"(パスワード|トークン|シークレット|APIキー|認証情報|認証キー)(?:\s*(?:は|を|に|へ|で|：|:|=|として))+\s*['\"]?([a-zA-Z0-9_\-.~!@#$%^&*+/=]{8,})['\"]?",
]



# Common key names for KEY=VALUE / KEY: VALUE redaction
_SECRET_KEY_REGEX = r"(?:api[_-]?key|password|passwd|token|secret|auth|access_token|private_key)"



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


def _looks_like_secret(value: str) -> bool:
    """Accurate heuristic: detect genuine credentials and reject placeholders, code & words."""
    if not value or len(value) < 8:
        return False

    # Real credentials (API keys, hashes, tokens, passwords) are strictly ASCII
    if not value.isascii():
        return False

    val_clean = value.strip("\"'`<>[]{}")
    val_lower = val_clean.lower()


    # 1. Reject code syntax & expressions (e.g. array indexing samples[0], func(x), obj.prop)
    if any(c in val_clean for c in "[](){}<>+=;,\\"):
        return False

    # 2. Exact match ignored / placeholder words
    if val_lower in PLACEHOLDER_KEYWORDS or val_clean.startswith("***"):
        return False

    # 3. Starts with placeholder prefix (e.g. 'your-admin-key', 'example_token')
    if any(val_lower.startswith(p) for p in PLACEHOLDER_PREFIXES):
        return False

    # 4. Trailing '_here', '-here', '_key', '-key' without digits
    if val_lower.endswith(("_here", "-here", "_key", "-key", "_token", "-token", "_secret", "-secret")) and not re.search(r"[0-9]", val_clean):
        return False

    # 5. Known real credential prefixes (override heuristics)
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
            return False

    class_count = sum([has_lower, has_upper, has_digit, has_special])

    # 3+ character classes with high entropy (e.g. Lower+Upper+Digit or Lower+Digit+Special)
    if class_count >= 3 and len(val_clean) >= 8:
        if _shannon_entropy(val_clean) >= 2.8:
            return True

    # 2 classes with digits and high entropy (12+ chars)
    if has_digit and class_count >= 2 and len(val_clean) >= 12:
        if _shannon_entropy(val_clean) >= 3.0:
            return True

    return False


def _apply_direct_patterns(text: str) -> str:
    """Apply compiled regex patterns from patterns.PATTERNS."""
    result = text
    for pattern in patterns.PATTERNS:
        result = re.sub(pattern, "***", result)
    return result


def _replace_kv_if_secret(match: re.Match) -> str:
    """Replace value in KEY=val only if it looks like a secret."""
    key_name = match.group(1)
    val = match.group(2)
    if _looks_like_secret(val):
        return f"{key_name}=***"
    return match.group(0)


def _replace_json_if_secret(match: re.Match) -> str:
    """Replace JSON value only if it looks like a secret."""
    key_prefix = match.group(1)
    val = match.group(3)
    if _looks_like_secret(val):
        return f'{key_prefix}"***"'
    return match.group(0)


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

    # 1. Apply known credential patterns
    result = _apply_direct_patterns(result)

    # 2. Redact KEY=value patterns (only genuine secrets)
    result = re.sub(
        rf"({_SECRET_KEY_REGEX})\s*=\s*([^\s\n]+)",
        _replace_kv_if_secret,
        result,
        flags=re.IGNORECASE
    )

    # 3. Redact JSON credential fields (preserving keys, only genuine secrets)
    result = re.sub(
        rf'("({_SECRET_KEY_REGEX})"\s*:\s*)"([^"]+)"',
        _replace_json_if_secret,
        result,
        flags=re.IGNORECASE
    )


    # 4. Redact YAML/colon key-value fields
    def _replace_yaml(m):
        prefix = m.group(1)
        val = m.group(2)
        if _looks_like_secret(val):
            return f"{prefix}***"
        return m.group(0)

    result = re.sub(
        rf'(?m)^(\s*{_SECRET_KEY_REGEX}\s*:\s*)["\']?([^"\'\s\n]+)["\']?',
        _replace_yaml,
        result,
        flags=re.IGNORECASE
    )

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

    # 1. Apply known credential patterns directly (scrubs raw tokens everywhere, including <think> blocks)
    result = _apply_direct_patterns(result)

    # 2. Redact KEY=value and key: value pairs in code blocks or text (only genuine secrets)
    result = re.sub(
        rf"({_SECRET_KEY_REGEX})\s*=\s*([^\s\n\"']+)",
        _replace_kv_if_secret,
        result,
        flags=re.IGNORECASE
    )
    result = re.sub(
        rf'("({_SECRET_KEY_REGEX})"\s*:\s*)"([^"]+)"',
        _replace_json_if_secret,
        result,
        flags=re.IGNORECASE
    )

    # 3. Natural language credential references (meta-discussion)
    def _nl_replacer(m):
        if len(m.groups()) >= 2:
            potential_secret = m.group(2)
            if potential_secret != "***" and _looks_like_secret(potential_secret):
                return m.group(0).replace(potential_secret, "***", 1)
        return m.group(0)

    for pattern in _NATURAL_LANGUAGE_PATTERNS:
        result = re.sub(pattern, _nl_replacer, result)

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

    # 2. For env dumps and .env reads, redact KEY=value
    if command and any(x in command.lower() for x in ["env", "printenv", "export", ".env"]):
        result = re.sub(
            r"([A-Z_0-9]*(?:password|token|api[_-]?key|secret|auth)[A-Z_0-9]*)\s*=\s*([^\s\n]+)",
            r"\1=***",
            result,
            flags=re.IGNORECASE
        )

    # 3. General: KEY=value pattern anywhere
    result = re.sub(
        rf"({_SECRET_KEY_REGEX})\s*=\s*([^\s\n]+)",
        r"\1=***",
        result,
        flags=re.IGNORECASE
    )

    if result != original:
        return result

    return None