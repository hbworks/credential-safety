"""Tests for credential safety plugin."""
import pytest
from plugins.credential_safety import patterns, hooks


class TestPatterns:
    def test_custom_patterns_compile(self):
        """Verify all patterns compile as valid regex."""
        from agent.redact import register_redaction_patterns
        count = register_redaction_patterns(patterns.PATTERNS, source="test")
        assert count == len(patterns.PATTERNS)


class TestHooks:
    def test_redact_tool_result_env_var(self):
        """Should redact KEY=value from tool results."""
        result = 'API_KEY=sk-1234567890abcdef'
        redacted = hooks.redact_tool_result("terminal", result)
        assert redacted is not None
        assert "sk-1234567890abcdef" not in redacted
        assert "***" in redacted
    
    def test_redact_llm_output_natural_language(self):
        """Should redact natural language credential references."""
        text = 'I changed the password to MySecurePass123!'
        redacted = hooks.redact_llm_output(text)
        # Entropy check should catch this
        assert redacted is not None
        assert "MySecurePass123" not in redacted or "***" in redacted
    
    def test_redact_terminal_env_dump(self):
        """Should redact env dumps."""
        output = 'PASSWORD=secret123\nUSER=admin'
        redacted = hooks.redact_terminal_output("env", output)
        assert redacted is not None
        assert "secret123" not in redacted
        assert "***" in redacted
        assert "USER=admin" in redacted  # Non-sensitive preserved
    
    def test_looks_like_secret(self):
        """Should identify likely secrets by entropy."""
        # High entropy = likely secret
        assert hooks._looks_like_secret("sk_abc123def456ghi789")
        assert hooks._looks_like_secret("MyP@ssw0rd!")
        
        # Low entropy = probably not a secret
        assert not hooks._looks_like_secret("admin")
        assert not hooks._looks_like_secret("user")