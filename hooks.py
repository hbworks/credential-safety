"""Hook implementations for credential safety."""
import re
import logging

logger = logging.getLogger(__name__)

# Patterns for natural language credential references
_NATURAL_LANGUAGE_PATTERNS = [
    r"(?i)(password|token|api[_-]?key|secret)\s+(?:is|was|used|changed):\s*['\"]?(\S+?)['\"]?(?:\s|\.)",
    r"(?i)(password|token|api[_-]?key|secret)\s+(?:to|for)\s+['\"]?(\S+?)['\"]?(?:\s|\.)",
    r"(?i)(?:the|a|an)\s+(password|token|api[_-]?key|secret)\s+['\"]?(\S+?)['\"]?",
]

def _looks_like_secret(value: str) -> bool:
    """Heuristic: does this look like random credentials?"""
    if len(value) < 8:
        return False
    
    # Too many special chars = likely a secret
    special_count = sum(1 for c in value if not c.isalnum())
    if len(value) > 0 and special_count / len(value) > 0.3:
        return True
    
    # High entropy = likely random
    unique_chars = len(set(value))
    return unique_chars / len(value) > 0.5


def redact_tool_result(tool_name: str, result: str, **kwargs) -> str | None:
    """Transform hook: redact credentials from tool results.
    
    Catches:
    - env var dumps (cat .env, printenv)
    - config file contents
    - JSON responses with credential fields
    """
    if not isinstance(result, str):
        return None
    
    original = result
    
    # Redact KEY=value patterns
    result = re.sub(
        r"(?i)(api_?key|password|token|secret|auth)=([^\s\n]+)",
        r"\1=***",
        result
    )
    
    # Redact JSON credential fields
    result = re.sub(
        r'"(?:api_?key|password|token|secret|access_token|authorization)"\s*:\s*"([^"]+)"',
        r'"***": "***"',
        result
    )
    
    if result != original:
        logger.debug(f"Redacted credential from tool {tool_name}")
        return result
    
    return None


def redact_llm_output(response_text: str, **kwargs) -> str | None:
    """Transform hook: redact natural language credential references.
    
    Catches model explaining what it fixed:
    - "I changed the password to secret123"
    - "API key was: sk-abc123..."
    - "The password is hidden now"
    """
    if not isinstance(response_text, str):
        return None
    
    original = response_text
    result = response_text
    
    # Try each natural language pattern
    for pattern in _NATURAL_LANGUAGE_PATTERNS:
        for match in re.finditer(pattern, response_text):
            if len(match.groups()) >= 2:
                key_type = match.group(1)  # "password", "token", etc.
                potential_secret = match.group(2)
                
                # Check if it looks like actual credentials
                if _looks_like_secret(potential_secret):
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
    
    # For env dumps and .env reads, redact KEY=value
    if command and any(x in (command.lower()) for x in ["env", "printenv", "export", ".env"]):
        result = re.sub(
            r"(?i)([A-Z_]*(?:password|token|api[_-]?key|secret|auth)[A-Z_]*)\s*=\s*([^\s\n]+)",
            r"\1=***",
            output
        )
        
        if result != original:
            logger.debug(f"Redacted env credentials from: {command}")
            return result
    
    # General: KEY=value pattern anywhere
    result = re.sub(
        r"(?i)(api_?key|password|token|secret|auth)=([^\s\n]+)",
        r"\1=***",
        output
    )
    
    if result != original:
        return result
    
    return None