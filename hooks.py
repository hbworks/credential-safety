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
    r"(?i)(password|token|api[_-]?key|secret|auth)\s+(?:is|was|used|changed|set to|updated to):\s*['\"]?(\S+?)['\"]?(?:\s|\.|$)",
    r"(?i)(password|token|api[_-]?key|secret|auth)\s+(?:to|for)\s+['\"]?(\S+?)['\"]?(?:\s|\.|$)",
    r"(?i)(?:the|a|an)\s+(password|token|api[_-]?key|secret|auth)\s+['\"]?(\S+?)['\"]?(?:\s|\.|$)",
    r"(?i)(password|token|api[_-]?key|secret|auth)\s*[:=]\s*['\"]?(\S+?)['\"]?(?:\s|\.|$)",

    # Japanese patterns
    r"(パスワード|トークン|シークレット|APIキー|認証情報|認証キー)\s*(?:は|を|に|：|:)\s*['\"]?(\S+?)['\"]?(?:\s|。|、|$)",
]

# Common key names for KEY=VALUE / KEY: VALUE redaction
_SECRET_KEY_REGEX = r"(api[_-]?key|password|passwd|token|secret|auth|access_token|private_key)"


def _looks_like_secret(value: str) -> bool:
    """Heuristic: does this look like random credentials or a sensitive secret?"""
    if not value or len(value) < 6:
        return False

    # Skip common placeholder values or markdown tags
    if value.lower() in ("***", "<redacted>", "none", "null", "undefined", "true", "false", "password", "secret"):
        return False

    # Obvious secret prefixes/formats
    if any(value.startswith(prefix) for prefix in ("sk-", "AKIA", "ghp_", "gho_", "glpat-", "xox", "eyJ")):
        return True

    # High percentage of special characters
    special_count = sum(1 for c in value if not c.isalnum())
    if len(value) > 0 and (special_count / len(value)) >= 0.2:
        return True

    # High entropy / character variety
    unique_chars = len(set(value))
    return (unique_chars / len(value)) > 0.45


def _apply_direct_patterns(text: str) -> str:
    """Apply compiled regex patterns from patterns.PATTERNS."""
    result = text
    for pattern in patterns.PATTERNS:
        result = re.sub(pattern, "***", result)
    return result


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

    # 2. Redact KEY=value patterns
    result = re.sub(
        rf"({_SECRET_KEY_REGEX})\s*=\s*([^\s\n]+)",
        r"\1=***",
        result,
        flags=re.IGNORECASE
    )

    # 3. Redact JSON credential fields (preserving keys)
    result = re.sub(
        rf'("({_SECRET_KEY_REGEX})"\s*:\s*)"([^"]+)"',
        r'\1"***"',
        result,
        flags=re.IGNORECASE
    )

    # 4. Redact YAML/colon key-value fields
    result = re.sub(
        rf'(?m)^(\s*{_SECRET_KEY_REGEX}\s*:\s*)["\']?([^"\'\s\n]+)["\']?',
        r'\1***',
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

    # 2. Redact KEY=value and key: value pairs in code blocks or text
    result = re.sub(
        rf"({_SECRET_KEY_REGEX})\s*=\s*([^\s\n\"']+)",
        r"\1=***",
        result,
        flags=re.IGNORECASE
    )
    result = re.sub(
        rf'("({_SECRET_KEY_REGEX})"\s*:\s*)"([^"]+)"',
        r'\1"***"',
        result,
        flags=re.IGNORECASE
    )

    # 3. Natural language credential references (meta-discussion)
    for pattern in _NATURAL_LANGUAGE_PATTERNS:
        for match in re.finditer(pattern, result):
            if len(match.groups()) >= 2:
                potential_secret = match.group(2)
                if potential_secret != "***" and _looks_like_secret(potential_secret):
                    result = result.replace(
                        match.group(0),
                        match.group(0).replace(potential_secret, "***"),
                        1
                    )

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