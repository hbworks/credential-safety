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

    def test_looks_like_secret_base64(self):
        """Should detect Base64 encoded secrets with + and = padding, and reject code equations."""
        # Genuine Base64 secrets
        self.assertTrue(hooks._looks_like_secret("k7+ABc1234567890def=="))
        self.assertTrue(hooks._looks_like_secret("dGVzdCt2YWx1ZTEyMzQ1Ng=="))
        self.assertTrue(hooks._looks_like_secret("aGVsbG8xMjM0NTY+"))

        # Code syntax equations or assignments should be rejected
        self.assertFalse(hooks._looks_like_secret("a=b"))
        self.assertFalse(hooks._looks_like_secret("x==y"))
        self.assertFalse(hooks._looks_like_secret("foo+bar=baz"))
        self.assertFalse(hooks._looks_like_secret("+1234567890"))

        # Non-placeholder values with double dots (not triple dots) should NOT be rejected as placeholders
        self.assertFalse(hooks._is_placeholder("foo..bar"))
        # Truncation ellipsis should be rejected as placeholder
        self.assertTrue(hooks._is_placeholder("sk-proj-...456"))

    def test_redact_expanded_secret_keys(self):
        """Should redact expanded environment variables like SECRET_KEY, CLIENT_SECRET, DATABASE_URL."""
        env_dump = (
            "SECRET_KEY=k7+ABc1234567890def==\n"
            "CLIENT_SECRET=client_secret_token_12345\n"
            "AUTH_TOKEN=auth_super_secret_token_789\n"
            "DATABASE_URL=postgres://user:super_secret_pass@localhost:5432/db\n"
            "NORMAL_VAR=hello_world\n"
        )
        redacted = hooks.redact_tool_result("terminal", env_dump)
        self.assertIsNotNone(redacted)
        self.assertNotIn("k7+ABc1234567890def==", redacted)
        self.assertNotIn("client_secret_token_12345", redacted)
        self.assertNotIn("auth_super_secret_token_789", redacted)
        self.assertIn("SECRET_KEY=***", redacted)
        self.assertIn("CLIENT_SECRET=***", redacted)
        self.assertIn("AUTH_TOKEN=***", redacted)
        self.assertIn("NORMAL_VAR=hello_world", redacted)

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

    def test_scanner_sync_base64_and_expanded_keys(self):
        """Should detect and sanitize Base64 secrets and expanded keys via LeakDetector."""
        from scan_credentials import LeakDetector

        detector = LeakDetector()
        text = (
            "SECRET_KEY=k7+ABc1234567890def==\n"
            "client_secret: dGVzdCt2YWx1ZTEyMzQ1Ng==\n"
            "Normal text with foo..bar placeholder\n"
        )
        findings = detector.scan_text(text, {"source_file": "app.env", "location": "Line 1-3"})
        self.assertGreaterEqual(len(findings), 2)

        sanitized = detector.sanitize_text(text)
        self.assertNotIn("k7+ABc1234567890def==", sanitized)
        self.assertNotIn("dGVzdCt2YWx1ZTEyMzQ1Ng==", sanitized)
        self.assertIn("foo..bar", sanitized)
        self.assertIn("SECRET_KEY=***", sanitized)
        self.assertIn("client_secret: ***", sanitized)

    def test_scan_sqlite_db_stream_and_fix(self):
        """Should stream SQLite rows, detect secrets, create backup, and redact in-place."""
        import tempfile
        import sqlite3
        from scan_credentials import LeakDetector, scan_sqlite_db

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "chat_history.sqlite"
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, role TEXT, content TEXT);")
            secret = "sk-proj-superSecretTestKey12345678901234567890"
            cur.execute("INSERT INTO messages (role, content) VALUES ('user', ?);", (f"My key is {secret}",))
            cur.execute("INSERT INTO messages (role, content) VALUES ('assistant', 'Understood, no secret here');")
            conn.commit()
            conn.close()

            detector = LeakDetector()
            recs, leaks = scan_sqlite_db(db_path, detector, fix=True)

            self.assertEqual(recs, 2)
            self.assertEqual(leaks, 1)
            self.assertTrue(db_path.with_suffix(f"{db_path.suffix}.bak").exists())

            # Verify in-place redaction in DB
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT content FROM messages WHERE id = 1;")
            updated_content = cur.fetchone()[0]
            conn.close()

            self.assertNotIn(secret, updated_content)
            self.assertIn("***", updated_content)

    def test_sqlite_transaction_rollback_on_error(self):
        """Should rollback changes if an exception occurs during batch update."""
        import tempfile
        import sqlite3
        from scan_credentials import LeakDetector, scan_sqlite_db

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_rollback.sqlite"
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, note TEXT);")
            secret = "sk-proj-superSecretTestKey12345678901234567890"
            cur.execute("INSERT INTO records (note) VALUES (?);", (f"API key: {secret}",))
            # Trigger abort on UPDATE to simulate write/constraint failure during transaction
            cur.execute(
                "CREATE TRIGGER abort_update BEFORE UPDATE ON records "
                "BEGIN SELECT RAISE(ABORT, 'Simulated write failure'); END;"
            )
            conn.commit()
            conn.close()

            detector = LeakDetector()
            # scan_sqlite_db catches error, rolls back transaction, prints error
            recs, leaks = scan_sqlite_db(db_path, detector, fix=True)

            # Check that content was rolled back and still contains original value
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT note FROM records WHERE id = 1;")
            val = cur.fetchone()[0]
            conn.close()

            self.assertIn(secret, val)

    def test_nested_yaml_fallback_without_pyyaml(self):
        """Should accurately parse deeply nested YAML secrets using pure-Python fallback parser."""
        import tempfile
        from unittest.mock import patch
        from scan_credentials import collect_known_secrets, _parse_yaml_fallback

        yaml_content = """
# Application Configuration
service:
  environment: production
  auth:
    deeply:
      nested:
        secret_token: "superSecretNestedToken12345"
    subdomain: "corp-team"
profiles:
  - name: primary
    api_key: "primaryApiKeySecret999"
"""
        # 1. Test fallback parser directly
        parsed = _parse_yaml_fallback(yaml_content)
        self.assertIn("service", parsed)
        self.assertEqual(
            parsed["service"]["auth"]["deeply"]["nested"]["secret_token"],
            "superSecretNestedToken12345"
        )

        # 2. Test collect_known_secrets when PyYAML import fails
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.yaml"
            cfg_file.write_text(yaml_content, encoding="utf-8")

            with patch.dict("sys.modules", {"yaml": None}):
                known = collect_known_secrets([Path(tmpdir)])

            extracted_values = [v[0] for v in known]
            self.assertIn("superSecretNestedToken12345", extracted_values)
            self.assertIn("primaryApiKeySecret999", extracted_values)

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

    def test_scan_json_output_does_not_leak_raw_secrets(self):
        """Verify --json output NEVER leaks raw plaintext secrets in findings or JSON payload."""
        import json
        import subprocess
        import tempfile

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "leaky.txt"
            secret_ghp = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
            secret_pwd = "mySuperSecretPassword123"
            test_file.write_text(
                f"token: {secret_ghp}\npassword = {secret_pwd}\n",
                encoding="utf-8"
            )

            res = subprocess.run(
                [sys.executable, str(scan_script), str(test_file), "--json"],
                capture_output=True,
                text=True
            )

            # Exit code should be 1 because leak was detected
            self.assertEqual(res.returncode, 1)

            data = json.loads(res.stdout)
            self.assertEqual(data["total_leaks_found"], 2)
            self.assertEqual(data["scan_errors"], 0)

            # Check that raw_match does not exist anywhere in findings, and match is strictly '***'
            for finding in data["findings"]:
                self.assertNotIn("raw_match", finding)
                self.assertEqual(finding["match"], "***")
                self.assertIn("raw_length", finding)

            # Check that raw plaintext secrets and their prefixes/suffixes are NOT present in JSON stdout
            self.assertNotIn(secret_ghp, res.stdout)
            self.assertNotIn(secret_ghp[:6], res.stdout)
            self.assertNotIn(secret_pwd, res.stdout)
            self.assertNotIn(secret_pwd[:6], res.stdout)

    def test_low_entropy_password_detection_and_redaction(self):
        """Verify low-entropy passwords with sensitive keys are detected and redacted across all layers."""
        from hooks import redact_tool_result, redact_llm_output
        from scan_credentials import LeakDetector

        # 1. Tool result (JSON & YAML & KEY=VALUE)
        raw_json = '{"user": "alice", "password": "admin123", "status": "ok"}'
        redacted_json = redact_tool_result("api_call", raw_json)
        self.assertIsNotNone(redacted_json)
        self.assertNotIn("admin123", redacted_json)
        self.assertIn('"password": "***"', redacted_json)

        raw_yaml = "auth:\n  password: simplepassword\n  role: admin"
        redacted_yaml = redact_tool_result("cat_config", raw_yaml)
        self.assertIsNotNone(redacted_yaml)
        self.assertNotIn("simplepassword", redacted_yaml)
        self.assertIn("password: ***", redacted_yaml)

        # 2. LLM output (Natural language English & Japanese)
        en_out = "The temporary password is simplepass1."
        redacted_en = redact_llm_output(en_out)
        self.assertIsNotNone(redacted_en)
        self.assertNotIn("simplepass1", redacted_en)
        self.assertIn("***", redacted_en)

        ja_out = "新しいパスワードは simplepass2 に変更されました。"
        redacted_ja = redact_llm_output(ja_out)
        self.assertIsNotNone(redacted_ja)
        self.assertNotIn("simplepass2", redacted_ja)
        self.assertIn("***", redacted_ja)

        # 3. Scanner LeakDetector
        detector = LeakDetector()
        text = 'db_password = "weakpassword123"'
        hits = detector.scan_text(text, {"source_file": "config.py"})
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["type"], "KeyValue (db_password)")
        self.assertEqual(hits[0]["match"], "***")
        self.assertNotIn("raw_match", hits[0])

        sanitized = detector.sanitize_text(text)
        self.assertEqual(sanitized, 'db_password = "***"')

        # 4. Placeholders should NOT be redacted
        placeholder_json = '{"password": "<your-password>", "token": "dummy"}'
        self.assertIsNone(redact_tool_result("api_call", placeholder_json))

    def test_cli_exit_codes(self):
        """Verify CLI exit codes: 0 for clean, 1 for leak detected, 2 for scan errors."""
        import subprocess
        import tempfile

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            # Case 1: Clean file -> exit code 0
            clean_file = Path(tmpdir) / "clean.txt"
            clean_file.write_text("hello world\nno secrets here\n", encoding="utf-8")
            res_clean = subprocess.run(
                [sys.executable, str(scan_script), str(clean_file)],
                capture_output=True,
                text=True
            )
            self.assertEqual(res_clean.returncode, 0)
            self.assertIn("No credential leaks found", res_clean.stdout)

            # Case 2: Leaked file -> exit code 1
            leaked_file = Path(tmpdir) / "leaked.txt"
            leaked_file.write_text("password = admin123\n", encoding="utf-8")
            res_leak = subprocess.run(
                [sys.executable, str(scan_script), str(leaked_file)],
                capture_output=True,
                text=True
            )
            self.assertEqual(res_leak.returncode, 1)
            self.assertIn("FOUND 1 POTENTIAL CREDENTIAL LEAK", res_leak.stdout)

            # Case 3: Non-existent path -> exit code 2
            missing_path = Path(tmpdir) / "nonexistent_file.txt"
            res_missing = subprocess.run(
                [sys.executable, str(scan_script), str(missing_path)],
                capture_output=True,
                text=True
            )
            self.assertEqual(res_missing.returncode, 2)
            self.assertIn("ENCOUNTERED 1 SCAN ERROR", res_missing.stdout)

    def test_backup_preserves_existing_bak(self):
        """Verify that existing .bak files are not overwritten when redacting SQLite DBs."""
        import subprocess
        import tempfile
        import sqlite3

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "data.sqlite"
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, note TEXT);")
            cur.execute("INSERT INTO users (note) VALUES ('secret token: ghp_1234567890abcdefghijklmnopqrstuvwxyz');")
            conn.commit()
            conn.close()

            # Pre-create an existing .bak file with special content
            orig_bak = Path(tmpdir) / "data.sqlite.bak"
            orig_bak.write_text("ORIGINAL_HEALTHY_BACKUP", encoding="utf-8")

            # Run --fix
            res = subprocess.run(
                [sys.executable, str(scan_script), str(db_path), "--fix"],
                capture_output=True,
                text=True
            )

            # The original .bak must be preserved intact!
            self.assertEqual(orig_bak.read_text(encoding="utf-8"), "ORIGINAL_HEALTHY_BACKUP")

            # A new timestamped backup must have been created
            new_backups = list(Path(tmpdir).glob("data.sqlite.bak.*"))
            self.assertEqual(len(new_backups), 1)
            self.assertTrue(new_backups[0].exists())

    def test_mask_secret_full_mask(self):
        """Verify mask_secret strictly outputs '***' for any secret without leaking prefixes or suffixes."""
        from scan_credentials import mask_secret

        self.assertEqual(mask_secret("admin123"), "***")
        self.assertEqual(mask_secret("1234567890"), "***")
        self.assertEqual(mask_secret("secret_pass"), "***")
        self.assertEqual(mask_secret("123456789012"), "***")
        self.assertEqual(mask_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz"), "***")
        self.assertEqual(mask_secret("AKIAIOSFODNN7EXAMPLE"), "***")

    def test_broken_auth_file_reports_error(self):
        """Verify that a corrupted auth.json / .env file is reported as a scan error (exit code 2)."""
        import json
        import subprocess
        import tempfile

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a broken JSON auth file
            broken_auth = Path(tmpdir) / "auth.json"
            broken_auth.write_text("{\"key\": \"unclosed json...", encoding="utf-8")

            res = subprocess.run(
                [sys.executable, str(scan_script), str(tmpdir), "--json"],
                capture_output=True,
                text=True
            )

            # Exit code must be 2 because scan encountered a configuration error
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)
            self.assertTrue(any("auth.json" in err for err in data["errors"]))

    def test_backup_preserves_existing_bak_even_on_same_second_collision(self):
        """Verify that multiple backups created within the same second use incremented counters and don't overwrite."""
        import subprocess
        import tempfile
        import sqlite3
        from datetime import datetime

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "data.sqlite"
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, note TEXT);")
            cur.execute("INSERT INTO users (note) VALUES ('secret token: ghp_1234567890abcdefghijklmnopqrstuvwxyz');")
            conn.commit()
            conn.close()

            # Pre-create standard .bak and a timestamped backup that simulates current second
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            orig_bak = Path(tmpdir) / "data.sqlite.bak"
            orig_bak.write_text("ORIGINAL_STANDARD_BACKUP", encoding="utf-8")
            orig_ts_bak = Path(tmpdir) / f"data.sqlite.bak.{ts}"
            orig_ts_bak.write_text("ORIGINAL_TIMESTAMPED_BACKUP", encoding="utf-8")

            # Run --fix
            res = subprocess.run(
                [sys.executable, str(scan_script), str(db_path), "--fix"],
                capture_output=True,
                text=True
            )

            # Both pre-existing files must be untouched
            self.assertEqual(orig_bak.read_text(encoding="utf-8"), "ORIGINAL_STANDARD_BACKUP")
            self.assertEqual(orig_ts_bak.read_text(encoding="utf-8"), "ORIGINAL_TIMESTAMPED_BACKUP")

            # A counter-appended backup (e.g. *.bak.<ts>_1) must exist
            incremented_backups = list(Path(tmpdir).glob(f"data.sqlite.bak.{ts}_*"))
            self.assertGreaterEqual(len(incremented_backups), 1)

    def test_corrupted_yaml_reports_error(self):
        """Verify that a corrupted YAML config/auth file reports a scan error (exit code 2),

        even when valid secret lines are present or PyYAML is not installed.
        """
        import json
        import subprocess
        import tempfile

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"

        # Case 1: Corrupted YAML with invalid indentation and unclosed bracket
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_yaml = Path(tmpdir) / "config.yaml"
            broken_yaml.write_text("service:\n  invalid_indent:\n- bad: [unclosed", encoding="utf-8")

            res = subprocess.run(
                [sys.executable, str(scan_script), str(tmpdir), "--json"],
                capture_output=True,
                text=True
            )

            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)
            self.assertTrue(any("config.yaml" in err for err in data["errors"]))

        # Case 2: Corrupted YAML that mixes a valid secret key with broken syntax
        # Ensures syntax error is never swallowed even if lines match key: value format
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_yaml_with_secret = Path(tmpdir) / "config.yaml"
            broken_yaml_with_secret.write_text(
                "app:\n  api_key: \"sk-1234567890abcdef12345678\"\n  broken_colon_no_space:bad\n  broken_list:\n[unclosed",
                encoding="utf-8"
            )

            res = subprocess.run(
                [sys.executable, str(scan_script), str(tmpdir), "--json"],
                capture_output=True,
                text=True
            )

            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)
            self.assertTrue(any("config.yaml" in err for err in data["errors"]))

        # Case 3: Pure-Python fallback parser directly raises ValueError on corrupted YAML without PyYAML
        from unittest.mock import patch
        from scan_credentials import collect_known_secrets, _parse_yaml_fallback

        with self.assertRaises(ValueError):
            _parse_yaml_fallback("service:\n  bad_syntax:\n- missing: [unclosed")

        with tempfile.TemporaryDirectory() as tmpdir:
            broken_yaml_no_pyyaml = Path(tmpdir) / "config.yaml"
            broken_yaml_no_pyyaml.write_text("service:\n  bad_indent:\n- err: [test", encoding="utf-8")
            errors_list = []
            with patch.dict("sys.modules", {"yaml": None}):
                collect_known_secrets([Path(tmpdir)], errors=errors_list)
            self.assertGreaterEqual(len(errors_list), 1)
            self.assertTrue(any("config.yaml" in err for err in errors_list))

    def test_malformed_env_reports_error(self):
        """Verify that .env files with various syntax errors (missing '=', unclosed quotes, empty keys,

        broken continuation lines, invalid key names) report scan error (exit code 2).
        """
        import json
        import subprocess
        import tempfile

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"

        # Case 1: Missing '='
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            broken_env.write_text("VALID_VAR=12345678\nTHIS_LINE_HAS_NO_EQUALS_SIGN\nANOTHER_VAR=abc", encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)
            self.assertTrue(any(".env" in err for err in data["errors"]))

        # Case 2: Unclosed quote (start quote without matching end quote, or single dangling quote)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            broken_env.write_text('API_KEY="unclosed_secret_string\nVALID=123', encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            broken_env.write_text('API_KEY="\nVALID=123', encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)

        # Case 3: Empty key
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            broken_env.write_text("=orphan_value\n", encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)

        # Case 4: Broken continuation line (trailing backslash without valid continuation)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            broken_env.write_text("API_KEY=value_with_broken_continuation\\\n", encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)
            self.assertTrue(any("continuation" in err for err in data["errors"]))

        # Case 5: Invalid key name (starts with digit or contains illegal characters/spaces)
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            broken_env.write_text("123_INVALID_KEY_NAME=secret123\n", encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)
            self.assertTrue(any("invalid key name" in err for err in data["errors"]))

        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            broken_env.write_text("INVALID KEY WITH SPACES=secret123\n", encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)
            self.assertTrue(any("invalid key name" in err for err in data["errors"]))

    def test_atomic_backup_concurrent_toctou_prevention(self):
        """Verify that _atomic_create_backup safely handles concurrent callers without TOCTOU race conditions."""
        import tempfile
        import concurrent.futures
        from scan_credentials import _atomic_create_backup

        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "test.db"
            src_file.write_text("DATABASE_CONTENT_TEST", encoding="utf-8")

            # Concurrently create 10 backups of the same file
            num_workers = 10
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = [executor.submit(_atomic_create_backup, src_file) for _ in range(num_workers)]
                created_paths = [f.result() for f in futures]

            # All created backup paths must be unique
            self.assertEqual(len(set(created_paths)), num_workers)
            # All files must exist and contain the original content intact
            for p in created_paths:
                self.assertTrue(p.exists())
                self.assertEqual(p.read_text(encoding="utf-8"), "DATABASE_CONTENT_TEST")

    def test_error_messages_do_not_leak_secret_snippets(self):
        """Verify that syntax error messages in YAML and .env NEVER leak secret fragments or raw snippets in --json errors."""
        import json
        import subprocess
        import tempfile

        scan_script = Path(__file__).resolve().parent.parent / "scan_credentials.py"

        # 1. Test .env syntax error with real-looking secret
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_env = Path(tmpdir) / ".env"
            secret_env = "sk-superSecretEnvTokenVal1234567890"
            broken_env.write_text(f'API_KEY="{secret_env}\n', encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)

            # Neither the full secret nor its prefix snippet should exist in stdout or errors
            self.assertNotIn(secret_env, res.stdout)
            self.assertNotIn(secret_env[:10], res.stdout)
            for err in data["errors"]:
                self.assertNotIn(secret_env, err)
                self.assertNotIn(secret_env[:10], err)

        # 2. Test YAML syntax error with real-looking secret
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_yaml = Path(tmpdir) / "config.yaml"
            secret_yaml = "ghp_yamlSecretBrokenVal1234567890abcdef"
            broken_yaml.write_text(f'auth:\n  token: [{secret_yaml}\n', encoding="utf-8")

            res = subprocess.run([sys.executable, str(scan_script), str(tmpdir), "--json"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 2)
            data = json.loads(res.stdout)
            self.assertGreaterEqual(data["scan_errors"], 1)

            # Neither the full secret nor its prefix snippet should exist in stdout or errors
            self.assertNotIn(secret_yaml, res.stdout)
            self.assertNotIn(secret_yaml[:10], res.stdout)
            for err in data["errors"]:
                self.assertNotIn(secret_yaml, err)
                self.assertNotIn(secret_yaml[:10], err)


if __name__ == "__main__":
    unittest.main()