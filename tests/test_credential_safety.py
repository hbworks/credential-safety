"""Tests for credential safety plugin."""
import os
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

    def test_placeholder_not_redacted(self):
        """Placeholders and documentation commands should NOT be redacted."""
        text = 'echo "MEM0_API_KEY=your-admin-api-key" >> ~/.hermes/.env'
        redacted = hooks.redact_llm_output(text)
        # Should remain intact
        self.assertIsNone(redacted)

        tool_res = 'API_KEY=your_api_key_here\nCONFIG=default'
        redacted_tool = hooks.redact_tool_result("terminal", tool_res)
        self.assertIsNone(redacted_tool)

    def test_redact_new_patterns(self):
        """Should redact Google, GitHub PAT, Stripe, and HuggingFace tokens."""
        cases = [
            ("Google API Key", "AIzaSyD-1234567890abcdefghijklmnopqrst", True),
            ("Google OAuth", "ya29.a0AfH6SMD-1234567890abcdefghij", True),
            ("GitHub PAT", "github_pat_11AAAAAAA01234567890ab_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr", True),
            ("Stripe Secret", "sk_live_" + "a" * 24, True),
            ("HuggingFace", "hf_abcdefghijklmnopqrstuvwxyz123456", True),
        ]
        for name, token, should_redact in cases:
            text = f"API Token for {name}: {token}"
            redacted = hooks.redact_llm_output(text)
            self.assertIsNotNone(redacted, f"Failed to redact {name}")
            self.assertNotIn(token, redacted, f"Token leaked in {name}")
            self.assertIn("***", redacted)

    def test_looks_like_secret(self):
        """Should identify likely secrets by entropy / structure and reject placeholders."""
        # High entropy or secret prefix = likely secret
        self.assertTrue(hooks._looks_like_secret("sk_abc123def456ghi789"))
        self.assertTrue(hooks._looks_like_secret("MyP@ssw0rd!"))
        self.assertTrue(hooks._looks_like_secret("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(hooks._looks_like_secret("AIzaSyD-1234567890abcdefghijklmnopqrst"))
        self.assertTrue(hooks._looks_like_secret("github_pat_11AAAAAAA01234567890ab_abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqr"))
        self.assertTrue(hooks._looks_like_secret("hf_abcdefghijklmnopqrstuvwxyz123456"))

        # Placeholders / common words = not a secret
        self.assertFalse(hooks._looks_like_secret("your-admin-api-key"))
        self.assertFalse(hooks._looks_like_secret("your_api_key_here"))
        self.assertFalse(hooks._looks_like_secret("example-api-key"))
        self.assertFalse(hooks._looks_like_secret("admin"))
        self.assertFalse(hooks._looks_like_secret("user"))
        self.assertFalse(hooks._looks_like_secret("***"))
        self.assertFalse(hooks._looks_like_secret("password"))

    def test_redact_llm_output_yaml_colon_format(self):
        """Should redact key: value format in YAML/code blocks from LLM output."""
        yaml_text = "config:\n  password: MySuperSecurePassword999!\n  mode: production"
        redacted = hooks.redact_llm_output(yaml_text)
        self.assertIsNotNone(redacted)
        self.assertNotIn("MySuperSecurePassword999!", redacted)
        self.assertIn("password: ***", redacted)
        self.assertIn("mode: production", redacted)

    def test_redact_multiline_private_key(self):
        """Should redact multiline private keys."""
        priv_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0+abc123def456==\n"
            "-----END RSA PRIVATE KEY-----"
        )
        text = f"Here is the key:\n{priv_key}\nPlease keep it safe."
        redacted = hooks.redact_llm_output(text)
        self.assertIsNotNone(redacted)
        self.assertNotIn("MIIEowIBAAKCAQEA0+abc123def456==", redacted)
        self.assertIn("***", redacted)


class TestScanner(unittest.TestCase):
    def test_collect_secrets_from_yaml(self):
        """Should extract authentic API keys from config.yaml."""
        import tempfile
        from scan_credentials import collect_known_secrets, LeakDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            cfg_file = tmp_path / "config.yaml"
            secret_key = "9knB7zK1pQ8vW2xM5tL0sR4uN6yP9aC3dE7fG1hJ5kL8mO2pQ6rS0tU4vW8xY2zA1"
            cfg_file.write_text(f"""
backlog:
  BACKLOG_API_KEY: "{secret_key}"
  subdomain: "myteam"
""", encoding="utf-8")

            known = collect_known_secrets([tmp_path])
            self.assertEqual(len(known), 1)
            self.assertEqual(known[0][0], secret_key)
            self.assertIn("BACKLOG_API_KEY", known[0][1])

            detector = LeakDetector(known_secrets=known)
            log_text = f"Logged in with Backlog key: {secret_key}"
            findings = detector.scan_text(log_text, {"file": "test.log", "location": "Line 1"})
            self.assertEqual(len(findings), 1)
            self.assertIn("Exact Match", findings[0]["type"])

    def test_scan_file_multiline_private_key(self):
        """Should detect multiline private keys in text/log files."""
        import tempfile
        from scan_credentials import LeakDetector, scan_json_or_text_file

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "app.log"
            content = (
                "2026-09-03 INFO Starting service\n"
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEowIBAAKCAQEA0+abc123def456==\n"
                "-----END RSA PRIVATE KEY-----\n"
                "2026-09-03 INFO Service stopped\n"
            )
            log_file.write_text(content, encoding="utf-8")

            detector = LeakDetector()
            recs, leaks = scan_json_or_text_file(log_file, detector)
            self.assertEqual(leaks, 1)
            self.assertEqual(len(detector.findings), 1)
            self.assertEqual(detector.findings[0]["location"], "Line 2")

    def test_scan_bearer_token_with_padding(self):
        """Should detect and sanitize Bearer tokens ending with base64 padding '='."""
        from scan_credentials import LeakDetector

        detector = LeakDetector()
        text = "Authorization: Bearer mySecretTokenValue123456="
        findings = detector.scan_text(text, {"source_file": "api.log", "location": "Line 1"})
        self.assertEqual(len(findings), 1)

        sanitized = detector.sanitize_text(text)
        self.assertNotIn("mySecretTokenValue123456=", sanitized)
        self.assertIn("***", sanitized)

    def test_all_patterns_acceptable_by_hermes_core(self):
        """Verify that 100% of patterns are accepted by Hermes core register_redaction_patterns if present."""
        try:
            hermes_home = os.environ.get("HERMES_HOME", "").strip() or os.path.expanduser("~/.hermes")
            sys.path.insert(0, os.path.join(hermes_home, "hermes-agent"))
            from agent.redact import register_redaction_patterns
            accepted = register_redaction_patterns(patterns.PATTERNS, source="test_suite")
            self.assertEqual(accepted, len(patterns.PATTERNS))
        except ImportError:
            self.skipTest("Hermes agent source not found in standard location")


if __name__ == "__main__":
    unittest.main()