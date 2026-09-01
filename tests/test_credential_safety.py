"""Tests for credential safety plugin."""
import re
import unittest
import sys
from pathlib import Path

# Add plugin dir to path if needed
plugin_dir = Path(__file__).resolve().parent.parent
if str(plugin_dir) not in sys.path:
    sys.path.insert(0, str(plugin_dir))

import patterns
import hooks


class TestPatterns(unittest.TestCase):
    def test_custom_patterns_compile(self):
        """Verify all patterns compile as valid regex."""
        for p in patterns.PATTERNS:
            compiled = re.compile(p)
            self.assertIsNotNone(compiled)
        self.assertGreater(len(patterns.PATTERNS), 0)


class TestHooks(unittest.TestCase):
    def test_redact_tool_result_env_var(self):
        """Should redact KEY=value from tool results."""
        result = 'API_KEY=sk-1234567890abcdef123456'
        redacted = hooks.redact_tool_result("terminal", result)
        self.assertIsNotNone(redacted)
        self.assertNotIn("sk-1234567890abcdef123456", redacted)
        self.assertIn("***", redacted)

    def test_redact_tool_result_json_preserves_keys(self):
        """Should redact JSON values while preserving keys."""
        result = '{"status": "ok", "api_key": "secret_value_12345", "user": "masato"}'
        redacted = hooks.redact_tool_result("api_client", result)
        self.assertIsNotNone(redacted)
        self.assertIn('"api_key": "***"', redacted)
        self.assertIn('"user": "masato"', redacted)

    def test_redact_llm_output_natural_language_en(self):
        """Should redact natural language credential references in English."""
        text = 'I changed the password to MySecurePass123!'
        redacted = hooks.redact_llm_output(text)
        self.assertIsNotNone(redacted)
        self.assertNotIn("MySecurePass123", redacted)
        self.assertIn("***", redacted)

    def test_redact_llm_output_natural_language_ja(self):
        """Should redact natural language credential references in Japanese."""
        text = '修正したAPIキーは SuperSecretApiKey999! です。'
        redacted = hooks.redact_llm_output(text)
        self.assertIsNotNone(redacted)
        self.assertNotIn("SuperSecretApiKey999", redacted)
        self.assertIn("***", redacted)

    def test_redact_llm_output_thinking_block(self):
        """Should redact credentials leaked inside reasoning / thinking blocks."""
        thinking = '<think>\nThe user previously used AWS key AKIAIOSFODNN7EXAMPLE.\nLet me fix this.\n</think>\nDone!'
        redacted = hooks.redact_llm_output(thinking)
        self.assertIsNotNone(redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn("***", redacted)

    def test_redact_llm_output_well_known_tokens(self):
        """Should redact well-known token formats even without explicit context."""
        text = 'Here is the token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12'
        redacted = hooks.redact_llm_output(text)
        self.assertIsNotNone(redacted)
        self.assertNotIn("ghp_1234567890abcdefghijklmnopqrstuvwxyz12", redacted)
        self.assertIn("***", redacted)

    def test_redact_terminal_env_dump(self):
        """Should redact env dumps."""
        output = 'PASSWORD=secret123\nUSER=admin'
        redacted = hooks.redact_terminal_output("env", output)
        self.assertIsNotNone(redacted)
        self.assertNotIn("secret123", redacted)
        self.assertIn("***", redacted)
        self.assertIn("USER=admin", redacted)  # Non-sensitive preserved

    def test_looks_like_secret(self):
        """Should identify likely secrets by entropy / structure."""
        # High entropy or secret prefix = likely secret
        self.assertTrue(hooks._looks_like_secret("sk_abc123def456ghi789"))
        self.assertTrue(hooks._looks_like_secret("MyP@ssw0rd!"))
        self.assertTrue(hooks._looks_like_secret("AKIAIOSFODNN7EXAMPLE"))

        # Low entropy / placeholders = not a secret
        self.assertFalse(hooks._looks_like_secret("admin"))
        self.assertFalse(hooks._looks_like_secret("user"))
        self.assertFalse(hooks._looks_like_secret("***"))
        self.assertFalse(hooks._looks_like_secret("password"))


if __name__ == "__main__":
    unittest.main()