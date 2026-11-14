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
        """Generated token-shaped fixtures exercise prefix checks without storing a key."""
        cases = [
            ("Google API Key", "AIza" + "A" * 35),
            ("Google OAuth", "ya29." + "A" * 20),
            ("GitHub classic", "ghp_" + "a" * 36),
            ("GitHub PAT", "github_pat_" + "a" * 60),
            ("AWS access key ID", "AKIA" + "A" * 16),
            ("Stripe Secret", "sk_live_" + "a" * 24),
            ("HuggingFace", "hf_" + "a" * 30),
        ]
        for name, token in cases:
            with self.subTest(name=name):
                self.assertTrue(hooks._looks_like_secret(token), f"Prefix check failed for {name}")
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

    def test_backup_does_not_overwrite_existing_baks(self):
        """Verify that existing standard and timestamped .bak files are both preserved when --fix runs."""
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

            # Pre-create the standard .bak plus one timestamped backup. The timestamp is a
            # fixed string: deriving it from "now" races the clock across a second boundary.
            orig_bak = Path(tmpdir) / "data.sqlite.bak"
            orig_bak.write_text("ORIGINAL_STANDARD_BACKUP", encoding="utf-8")
            orig_ts_bak = Path(tmpdir) / "data.sqlite.bak.20000101_000000"
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

            # A new timestamped backup must have been created next to the existing ones
            created = [p for p in Path(tmpdir).glob("data.sqlite.bak.*") if p != orig_ts_bak]
            self.assertGreaterEqual(len(created), 1)

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


class TestCoverageGaps(unittest.TestCase):
    """Regressions for the shapes Hermes core does not catch on its own.

    Core's ``redact_sensitive_text`` covers vendor-prefixed tokens and plain
    ``KEY=value`` assignments, but not: escaped (json.dumps) payloads, YAML/JSON
    values on the terminal surface, or natural-language mentions.
    """

    ESCAPED_JSON = 's3cr3tValue99XYZ'
    LOW_ENTROPY_PW = 'hunter2abc'
    BARE_TOKEN = 'Zx9Qw8Er7Ty6Ui5Op4'

    def test_escaped_json_inside_tool_result(self):
        import json as _json
        result = _json.dumps({
            "content": '1|OPENAI_API_KEY=x\n2|{"client_secret": "%s"}' % self.ESCAPED_JSON
        })
        redacted = hooks.redact_tool_result("read_file", result)
        self.assertIsNotNone(redacted)
        self.assertNotIn(self.ESCAPED_JSON, redacted)
        self.assertIn('\\"***\\"', redacted)

    def test_escaped_yaml_with_line_number_prefix(self):
        import json as _json
        result = _json.dumps({
            "content": "1|service:\n2|  password: %s\n3|  mode: production" % self.LOW_ENTROPY_PW
        })
        redacted = hooks.redact_tool_result("read_file", result)
        self.assertIsNotNone(redacted)
        self.assertNotIn(self.LOW_ENTROPY_PW, redacted)
        self.assertIn("password: ***", redacted)
        self.assertIn("production", redacted)  # non-sensitive value preserved

    def test_natural_language_in_tool_result(self):
        text = "api key is %s (rotated today)" % self.BARE_TOKEN
        redacted = hooks.redact_tool_result("web_extract", text)
        self.assertIsNotNone(redacted)
        self.assertNotIn(self.BARE_TOKEN, redacted)
        self.assertIn("***", redacted)

    def test_natural_language_keeps_benign_words(self):
        for text in ("the token is expired", "the api key is required", "auth: required"):
            self.assertIsNone(
                hooks.redact_tool_result("web_extract", text),
                msg="benign prose was masked: %s" % text,
            )

    def test_terminal_json_and_yaml_shapes(self):
        cases = [
            ('{"client_secret": "%s"}' % self.ESCAPED_JSON, self.ESCAPED_JSON),
            ("password: %s" % self.LOW_ENTROPY_PW, self.LOW_ENTROPY_PW),
            ("12:password: %s" % self.LOW_ENTROPY_PW, self.LOW_ENTROPY_PW),
        ]
        for output, secret in cases:
            redacted = hooks.redact_terminal_output("cat app.log", output)
            self.assertIsNotNone(redacted, msg="not redacted: %s" % output)
            self.assertNotIn(secret, redacted)
            self.assertIn("***", redacted)

    def test_terminal_natural_language_ja(self):
        output = "パスワードは Passw0rd2024! です"
        redacted = hooks.redact_terminal_output("cat app.log", output)
        self.assertIsNotNone(redacted)
        self.assertNotIn("Passw0rd2024!", redacted)
        self.assertIn("***", redacted)

    def test_escaped_payload_does_not_swallow_following_lines(self):
        """The KEY=value pass must stop at a backslash escape, not eat the next line."""
        import json as _json
        result = _json.dumps({"content": "OPENAI_API_KEY=x\n2|user: bob"})
        redacted = hooks.redact_tool_result("read_file", result) or result
        self.assertIn("2|user: bob", redacted)


class TestReviewFixes(unittest.TestCase):
    """Regressions for the 2026-11 review findings (numeric settings, layer parity, YAML, Bearer)."""

    def test_numeric_settings_are_not_masked(self):
        from hooks import _should_mask_value
        for key, value in (("max_tokens", "32768"),
                           ("proactive_prune_min_reclaim_tokens", "4096"),
                           ("max_output_tokens", "8192")):
            self.assertFalse(_should_mask_value(key, value), msg="%s treated as a secret" % key)
        for key, value in (("db_password", "admin123"),
                           ("api_key", "sk-proj-QwErTy1234567890"),
                           ("token", "token1234567890")):
            self.assertTrue(_should_mask_value(key, value), msg="%s no longer masked" % key)

    def test_scanner_shares_hook_patterns(self):
        import scan_credentials as S
        import hooks as H
        self.assertEqual([p for _, p in S.PATTERNS], [p for _, p in H.COMPILED_PATTERNS])
        self.assertEqual(S.NATURAL_LANG_REGEX, list(H._NL_COMPILED))

    def test_scanner_matches_hook_prose_and_glued_tokens(self):
        import scan_credentials as S
        import hooks as H
        cases = ("api key is Zx9Qw8Er7Ty6Ui5Op4 done",
                 "xxghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
        for text in cases:
            self.assertIsNotNone(H.redact_tool_result("t", text), msg="hook missed: %s" % text)
            self.assertTrue(S.LeakDetector().scan_text(text, {}), msg="scanner missed: %s" % text)

    def test_yaml_fallback_block_scalar_and_multidoc(self):
        from scan_credentials import _parse_yaml_fallback
        parsed = _parse_yaml_fallback("auth:\n  token: |\n    blockval12345\n  name: x\n")
        self.assertEqual(parsed["auth"]["token"], "blockval12345")
        self.assertEqual(parsed["auth"]["name"], "x")

        folded = _parse_yaml_fallback("auth:\n  secret: >-\n    folded12345\n")
        self.assertEqual(folded["auth"]["secret"], "folded12345")

        multi = _parse_yaml_fallback("a:\n  token: first12345\n---\nb:\n  token: second12345\n")
        self.assertEqual(multi["a"]["token"], "first12345")
        self.assertEqual(multi["b"]["token"], "second12345")

    def test_yaml_fallback_flow_map_list_items_and_json(self):
        from scan_credentials import _parse_yaml_fallback
        flow = _parse_yaml_fallback("auth: {api_key: flowval12345, name: svc}\n")
        self.assertEqual(flow["auth"]["api_key"], "flowval12345")
        self.assertEqual(flow["auth"]["name"], "svc")

        listed = _parse_yaml_fallback(
            "keys:\n  - name: a\n    api_key: listval12345\n  - name: b\n    api_key: listval67890\n")
        self.assertEqual([i["api_key"] for i in listed["keys"]], ["listval12345", "listval67890"])

        js = _parse_yaml_fallback('{"auth": {"token": "jsonval12345"}}')
        self.assertEqual(js["auth"]["token"], "jsonval12345")

    def test_yaml_fallback_empty_value_is_null(self):
        from scan_credentials import _parse_yaml_fallback
        parsed = _parse_yaml_fallback("auth:\n  token:\n  name: x\n")
        # A key with no value is null (models as None or an empty mapping, never an error)
        self.assertIn(parsed["auth"]["token"], (None, {}))
        self.assertEqual(parsed["auth"]["name"], "x")

    def test_yaml_parser_reexport_contract(self):
        import scan_credentials as S
        import yaml_fallback
        self.assertIs(S._parse_yaml_fallback, yaml_fallback.parse_yaml)
        self.assertEqual(yaml_fallback.parse_yaml("a:\n  token: v12345678\n"),
                         {"a": {"token": "v12345678"}})

    def test_bearer_fixture_not_flagged_real_token_is(self):
        import scan_credentials as S
        for text in ("Authorization: Bearer test-tok-abc",
                     "Authorization: Bearer your-token-here",
                     "Authorization: Bearer example-abc-def"):
            self.assertFalse(S.LeakDetector().scan_text(text, {}), msg="false positive: %s" % text)
        self.assertTrue(S.LeakDetector().scan_text("Authorization: Bearer ab12cd34ef56gh78", {}))


class TestCodeFalsePositives(unittest.TestCase):
    """Regressions: code references, version literals and source-file reads must survive intact.

    The key-context fallback used to mask anything under a sensitive key, so reading a
    source file turned `password: user.password` into `password: ***`. These tests pin the
    gate that stops it without weakening real-secret detection.
    """

    CODE_PATH = "/Users/masato/Dev/app/auth.py"

    def test_code_expression_not_masked(self):
        """Attribute refs, calls, env lookups, templates and shell refs are references, not secrets."""
        for key, value in (("password", "user.password"),
                           ("token", "get_token()"),
                           ("api_key", 'os.environ.get("BACKLOG_API_KEY")'),
                           ("secret", "self.client.secret"),
                           ("password", 'f"{pw}"'),
                           ("password", "$DB_PASSWORD")):
            self.assertFalse(hooks._should_mask_value(key, value), msg="%s=%s" % (key, value))
        self.assertTrue(hooks._looks_like_code_expr("config.get_key()"))

        for src in ("auth:\n  password: user.password\n",
                    "token: get_token()",
                    'api_key = os.environ.get("BACKLOG_API_KEY")',
                    '{"api_key": "config.get_key()"}',
                    'password=f"{pw}"',
                    "password=$DB_PASSWORD",
                    "secret: self.client.secret"):
            # both the flat kwarg shape and the real Hermes `args=` payload
            for kwargs in ({"path": self.CODE_PATH}, {"args": {"path": self.CODE_PATH}}):
                self.assertIsNone(hooks.redact_tool_result("read_file", src, **kwargs), msg=src)

    def test_semver_path_not_masked(self):
        """Version literals and versioned paths are not credentials."""
        for value in ("v1.2.3", "1.2.3", "2.3.1-beta.1",
                      "node/18.17.0/bin/node", "/usr/local/lib/tokens.d/1.2.3"):
            for key in ("token", "api_key", "secret"):
                self.assertFalse(hooks._should_mask_value(key, value), msg="%s=%s" % (key, value))
        self.assertIsNone(
            hooks.redact_tool_result("read_file", "token: v1.2.3", path="/srv/app/version.txt")
        )
        # ... while a real high-entropy credential under the same key still masks
        self.assertTrue(hooks._should_mask_value("token", "token1234567890"))

    def test_low_entropy_password_still_masked(self):
        """The code gate must not swallow genuine low-entropy passwords."""
        self.assertTrue(hooks._should_mask_value("password", "admin123"))
        cases = (
            ('{"user": "alice", "password": "admin123"}', {"path": self.CODE_PATH}),
            ("auth:\n  password: admin123", {"path": "/srv/app/config.yaml"}),
            ("db_password=admin123", {}),
        )
        for src, kwargs in cases:
            out = hooks.redact_tool_result("read_file", src, **kwargs)
            self.assertIsNotNone(out, msg=src)
            self.assertNotIn("admin123", out)

    def test_e164_phone_still_masked(self):
        """E.164 numbers start with '+' and must keep being masked under a sensitive key."""
        self.assertTrue(hooks._should_mask_value("token", "+819012345678"))
        self.assertTrue(hooks._should_mask_value("api_key", "+14155550123"))
        out = hooks.redact_tool_result(
            "read_file", '{"auth_token": "+819012345678"}', path=self.CODE_PATH
        )
        self.assertIsNotNone(out)
        self.assertNotIn("819012345678", out)

    def test_source_file_still_redacts_literals_and_comments(self):
        """A code extension is not a free pass: quoted literals and comment prose still mask."""
        out = hooks.redact_tool_result(
            "read_file", 'const c = { password: "hunter2abc" };', path="/a/x.ts"
        )
        self.assertIsNotNone(out)
        self.assertNotIn("hunter2abc", out)

        out = hooks.redact_tool_result("read_file", "# the token is abc123def", path=self.CODE_PATH)
        self.assertIsNotNone(out)
        self.assertNotIn("abc123def", out)

        # References, annotations and version literals stay intact
        for src in ('const c = { password: user.password };', "token: Optional[str]",
                    'const v = "v1.2.3";'):
            self.assertIsNone(hooks.redact_tool_result("read_file", src, path="/a/x.ts"), msg=src)

    def test_url_query_credentials_still_masked(self):
        """A URL carrying userinfo or a sensitive query parameter is a credential."""
        for v in ("https://api.x.com/cb?token=p4ssw0rd99&a=1",
                  "https://user:pw@api.x.com/v1",
                  "postgres://user:p4ssw0rd@localhost:5432/db"):
            self.assertTrue(hooks._should_mask_value("token", v), msg=v)
        self.assertFalse(
            hooks._should_mask_value("token", "https://api.x.com/v1/items?page=2")
        )

    def test_code_like_passwords_still_masked(self):
        """Passwords that merely resemble code syntax must keep being masked."""
        for v in ("P@ss{word}123", "x->y12345", "pa$$word123", "My.P4ssw0rd"):
            self.assertTrue(hooks._should_mask_value("password", v), msg=v)

    def test_ambiguous_sensitive_value_without_path_is_masked(self):
        """Without source-path evidence, prefer masking an ambiguous credential-shaped value."""
        ambiguous = "password: a && b"
        self.assertIsNone(
            hooks.redact_tool_result("read_file", ambiguous, path=self.CODE_PATH),
            "a known source path identifies the expression as code",
        )
        self.assertEqual(hooks.redact_tool_result("read_file", ambiguous), "password: ***")


class TestUrlCredentialPaths(unittest.TestCase):
    """Credentials inside a URL, attached to a key that says nothing about secrets.

    `{"redirect_url": "https://user:pw@host/cb"}` never reached the key-named passes, and
    masking the whole value broke the surrounding JSON. Both are regressions now pinned here.
    """

    def test_json_url_userinfo_masked_and_json_stays_valid(self):
        import json as _json
        src = '{"redirect_url": "https://user:p4ssw0rd99@x.com/cb"}'
        out = hooks.redact_tool_result("api_call", src)
        self.assertIsNotNone(out)
        self.assertNotIn("p4ssw0rd99", out)
        self.assertEqual(_json.loads(out)["redirect_url"], "https://***@x.com/cb")

    def test_json_url_query_masked_without_eating_delimiters(self):
        import json as _json
        src = '{"redirect_url": "https://x.com/cb?token=p4ssw0rd99&a=1"}'
        out = hooks.redact_tool_result("api_call", src)
        self.assertIsNotNone(out)
        parsed = _json.loads(out)["redirect_url"]  # invalid JSON would raise here
        self.assertNotIn("p4ssw0rd99", parsed)
        self.assertTrue(parsed.endswith("&a=1"))

    def test_key_value_inside_a_json_string_keeps_its_delimiters(self):
        import json as _json
        src = '{"cmd": "export API_KEY=abc123def; echo hi"}'
        out = hooks.redact_tool_result("api_call", src)
        self.assertIsNotNone(out)
        cmd = _json.loads(out)["cmd"]
        self.assertNotIn("abc123def", cmd)
        self.assertIn("; echo hi", cmd)

    def test_url_credentials_masked_on_llm_and_terminal_surfaces(self):
        llm = hooks.redact_llm_output("Visit https://admin:S3cretPass@internal.example/cb now")
        self.assertIsNotNone(llm)
        self.assertNotIn("S3cretPass", llm)
        self.assertIn("internal.example", llm)  # host preserved for context

        term = hooks.redact_terminal_output(
            "curl x", "GET https://api.x/cb?api_key=xxxTOKENVALUE123&page=2"
        )
        self.assertIsNotNone(term)
        self.assertNotIn("xxxTOKENVALUE123", term)
        self.assertIn("&page=2", term)

        # A credential-free URL is left alone on every surface
        self.assertIsNone(
            hooks.redact_tool_result("api_call", "https://api.example.com/v1/items?page=2")
        )

    def test_short_auth_parameter_is_preserved_and_numeric_tokens_are_masked(self):
        import json as _json

        src = _json.dumps({"redirect_url": "https://api.example.invalid/cb?auth=required"})
        self.assertIsNone(hooks.redact_tool_result("api_call", src), msg=src)

        # Numeric values on actual token parameters may be OTPs; don't exempt them by value shape.
        for name in ("token", "access_token"):
            with self.subTest(name=name):
                src = _json.dumps({"redirect_url": f"https://api.example.invalid/cb?{name}=12345"})
                out = hooks.redact_tool_result("api_call", src)
                self.assertIsNotNone(out, msg=src)
                parsed = _json.loads(out)
                self.assertEqual(parsed["redirect_url"].split("?")[1], f"{name}=***")


    def test_metadata_parameter_names_are_not_credentials(self):
        """`token_id` / `token_type` are metadata about a credential, not the credential."""
        for name, val in (("token_id", "12345"), ("token_type", "bearer"),
                          ("token_name", "prod"), ("secret_id", "abc")):
            self.assertFalse(hooks._should_mask_value(name, val), msg=name)

        out = hooks.redact_tool_result(
            "api_call", "https://x/cb?token_id=12345&token_type=bearer&token=12345"
        )
        self.assertIsNotNone(out)
        self.assertIn("token_id=12345", out)
        self.assertIn("token_type=bearer", out)
        self.assertNotIn("token=12345", out)

        # A genuine high-entropy token stored under a metadata-looking name still masks
        self.assertTrue(hooks._should_mask_value("token_id", "a1B2c3D4e5F6g7H8i9J0k1L2"))


    def test_metadata_suffixes_do_not_hide_a_real_token(self):
        """`_header` and friends are no longer exempt; a long mixed-case run is a token."""
        self.assertTrue(hooks._should_mask_value("api_key_header", "AbCdEfGhIjKlMnOpQrStUvWx"))
        self.assertFalse(hooks._should_mask_value("api_key_header", "X-API-Key"))

        out = hooks.redact_tool_result("api_call", '{"api_key_header": "AbCdEfGhIjKlMnOpQrStUvWx"}')
        self.assertIsNotNone(out)
        self.assertNotIn("AbCdEfGhIjKlMnOpQrStUvWx", out)

    def test_opaque_token_in_url_path_masked(self):
        """A secret carried in the URL *path* is masked; UUIDs and doc examples are not."""
        opaque = "a1B2c3D4e5F6g7H8i9J0k1L2"
        src = '{"reset_url": "https://links.example.invalid/reset/%s"}' % opaque
        out = hooks.redact_tool_result("api_call", src)
        self.assertEqual(out, '{"reset_url": "https://links.example.invalid/reset/***"}')

        self.assertIsNone(hooks.redact_tool_result(
            "api_call", '{"url": "https://app/o/550e8400-e29b-41d4-a716-446655440000"}'))
        self.assertIsNone(hooks.redact_tool_result("api_call", "see https://user:pw@host/cb"))

        # A token that contains a dictionary word is still a token: word runs are not a signal
        self.assertIsNotNone(hooks.redact_tool_result(
            "api_call", "https://app/reset/tokenAbCdEfGhIjKlMnOpQrStUvWx123"))

        # A lowercase-heavy slug is not a token ...
        self.assertIsNone(hooks.redact_tool_result(
            "api_call", "https://shop.example/campaign/SummerSale2026Bundle"))
        # ... while a CamelCase slug with near-half uppercase is treated as one (documented FP)
        self.assertIsNotNone(hooks.redact_tool_result(
            "api_call", "https://shop.example/collection/iPhone15ProMaxBundleXYZ123"))

        # Only URL spans are touched: a filesystem path is never rewritten
        self.assertIsNone(hooks.redact_tool_result(
            "api_call", "/srv/app/releases/a1B2c3D4e5F6g7H8i9J0k1L2/main.py"))

    def test_short_opaque_path_token_masked(self):
        """An 18-character opaque segment is already a token."""
        self.assertIsNotNone(hooks.redact_tool_result("api_call", "https://app/r/xQ7Lm2Np9Rt4Vw8Zk1"))

    def test_path_token_followed_by_punctuation_is_masked(self):
        """Prose and markdown put `.`/`)`/`,` right after the token; it must still mask."""
        cases = (("https://app/reset/a1B2c3D4e5F6g7H8.", "***."),
                 ("[reset](https://app/reset/a1B2c3D4e5F6g7H8)", "***)"),
                 ("See https://app/reset/a1B2c3D4e5F6g7H8, go", "***,"))
        for src, expected in cases:
            out = hooks.redact_tool_result("api_call", src)
            self.assertIsNotNone(out, msg=src)
            self.assertIn(expected, out, msg=src)
            self.assertNotIn("a1B2c3D4e5F6g7H8", out)

    def test_lowercase_hex_path_token_masked(self):
        """A 32/40-character hex digest in a path is a token, even with no uppercase."""
        for seg in ("8f14e45fceea167a5a36dedd4bea2543",
                    "8f14e45fceea167a5a36dedd4bea2543a1b2c3d4e5f6a7b8"):
            out = hooks.redact_tool_result("api_call", "https://app/reset/" + seg)
            self.assertEqual(out, "https://app/reset/***", msg=seg)
        # A hyphenated UUID is not a bare digest: the URL pass itself must be a no-op
        uuid_url = "https://app/o/550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(hooks._apply_url_credentials(uuid_url), uuid_url)
        self.assertTrue(hooks._looks_like_structural_value(uuid_url))
        self.assertIsNone(hooks.redact_tool_result("api_call", uuid_url))

    def test_own_source_read_is_a_no_op(self):
        """Reading the plugin's own docstrings/regexes must not rewrite anything."""
        path = Path(hooks.__file__)
        self.assertIsNone(hooks.redact_tool_result(
            "read_file", path.read_text(encoding="utf-8"), args={"path": str(path)}))

    def test_source_url_masks_only_the_token(self):
        """A URL constant in source keeps its quotes; only the opaque segment is masked."""
        src = 'BASE = "https://api.example/v1/reset/a1B2c3D4e5F6g7H8"'
        out = hooks.redact_tool_result("read_file", src, args={"path": "/app/config.py"})
        self.assertIsNotNone(out)
        self.assertNotIn("a1B2c3D4e5F6g7H8", out)
        self.assertIn('"https://api.example/v1/reset/***"', out)


if __name__ == "__main__":
    unittest.main()