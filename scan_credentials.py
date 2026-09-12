#!/usr/bin/env python3
"""Credential Leak Scanner for Hermes Agent & SQLite DBs.

Zero-dependency standalone CLI tool to audit conversation history,
SQLite databases, and log files for leaked secrets and credentials.
"""

import argparse
import json
import os
import re
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try importing patterns from package, current directory, or script directory
try:
    from . import patterns
except (ImportError, ValueError):
    try:
        import patterns
    except ImportError:
        script_dir = str(Path(__file__).resolve().parent)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import patterns

# Detection Patterns compiled from patterns.PATTERNS
# (?i) などのインラインフラグを除いた実際の先頭文字列でホワイトリストを判定する
# ※ 正規表現内の \. は実文字 . に相当するため、両方向でチェックする
_NO_WORD_BOUNDARY_PREFIXES = (
    r"\b", "-----", "Bearer", "bearer", "Authorization", "authorization",
    "ya29.", "SG.", "xapp-", "xox", "(?:",
)

def _compile_pattern(p: str) -> re.Pattern:
    """patterns.PATTERNS の各文字列を適切に compile する。
    (?i) 等のインラインフラグや . を含む先頭パターンは \b を付与せず compile する。
    """
    # インラインフラグ (?i), (?m) 等を除去して実質的な先頭を取得
    stripped = re.sub(r"^\(\?[imsx]+\)", "", p)
    # 正規表現の \. → 実文字 . に変換（ホワイトリスト比較用）
    stripped_plain = stripped.replace(r"\.", ".")
    if any(stripped_plain.startswith(pfx) for pfx in _NO_WORD_BOUNDARY_PREFIXES):
        return re.compile(p)
    return re.compile(rf"\b(?:{p})\b")

PATTERNS = [
    ("Known Secret Pattern", _compile_pattern(p))
    for p in patterns.PATTERNS
]





SECRET_KEY_REGEX = re.compile(
    r"[\"']?(?<![a-zA-Z0-9_])(api[_-]?key|password|passwd|auth[_-]?token|access[_-]?token|refresh[_-]?token|secret[_-]?key|secret|token)(?![a-zA-Z0-9_])[\"']?\s*[:=]\s*[\"']?([^'\"\s\n,})\];>]+)[\"']?",
    re.IGNORECASE
)


NATURAL_LANG_REGEX = [
    re.compile(r"(?i)(?<![a-zA-Z0-9_])(password|token|api[_-]?key|secret|auth)(?![a-zA-Z0-9_])(?:\s+(?:is|was|used|changed|set|updated|generated|configured))*(?:\s*(?:is|was|to|for|as|into|:|:=|=|：))+\s*['\"]?([^\s'\"!.,;:]+)['\"]?(?:\s|\.|$|,|!|。|;)"),
    re.compile(r"(パスワード|トークン|シークレット|APIキー|認証情報|認証キー)(?:\s*(?:は|を|に|へ|で|：|:|=|として))+\s*['\"]?([a-zA-Z0-9_\-.~!@#$%^&*+/=]{8,})['\"]?"),
]



IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", "site-packages",
    "skills", "optional-skills", "references", "docs", "tests", "benchmarks",
    "training", "examples", "build", "dist", ".cache",
    "website", "i18n", "docusaurus", "site", "static", "assets", "locales",
    "hermes-agent", "templates"
}

# Authentic credential config files that are INTENDED to store secrets (should not be treated as leaks or broken by --fix)
INTENDED_AUTH_FILE_NAMES = {
    "auth.json", "nous_auth.json", ".env", "credentials.json", "secrets.json",
    "token.json", "tokens.json", "google_token.json", "google_credentials.json",
    "config.yaml", "config.yml", "settings.yaml", "settings.yml", "secrets.yaml", "secrets.yml",
    "hermes.yaml", "hermes.yml", "id_rsa", "id_ed25519", "key.pem", "cert.pem"
}


def is_intended_auth_file(file_path: Path) -> bool:
    """Check if a file is an authentic credential storage file (e.g. auth.json, config.yaml, .env)."""
    name_lower = file_path.name.lower()
    if name_lower in INTENDED_AUTH_FILE_NAMES:
        return True
    if name_lower.startswith(".env") or name_lower.endswith(".env"):
        return True
    if name_lower.endswith((
        "_auth.json", "-auth.json", "_token.json", "-token.json",
        "_credentials.json", "-credentials.json", "_secret.json", "-secret.json",
        "_auth.yaml", "-auth.yaml", "_token.yaml", "-token.yaml",
        "_config.yaml", "-config.yaml", "_secret.yaml", "-secret.yaml",
        "_auth.yml", "-auth.yml", "_token.yml", "-token.yml",
        "_config.yml", "-config.yml", "_secret.yml", "-secret.yml"
    )):
        return True
    if name_lower.startswith(("client_secret", "service_account", "gcp_credentials", "firebase_credentials")):
        return True
    return False




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


def looks_like_secret(value: str) -> bool:
    """Accurate heuristic: detect genuine credentials and reject placeholders, code & words."""
    if not value or len(value) < 8:
        return False

    # Real credentials (API keys, hashes, tokens, passwords) are strictly ASCII
    if not value.isascii():
        return False

    val_clean = value.strip("\"'`<>[]{}")
    val_lower = val_clean.lower()


    # 1. Reject already masked / truncated values (e.g. 'sk-123...456', '***', '..')
    if ".." in val_clean or "***" in val_clean or "<" in val_clean or ">" in val_clean:
        return False

    # 2. Reject code syntax & expressions (e.g. array indexing samples[0], func(x), obj.prop)
    if any(c in val_clean for c in "[](){}+=;,\\"):
        return False

    # 3. Exact match ignored / placeholder words
    if val_lower in PLACEHOLDER_KEYWORDS:
        return False

    # 4. Starts with placeholder prefix (e.g. 'your-admin-key', 'example_token')
    if any(val_lower.startswith(p) for p in PLACEHOLDER_PREFIXES):
        return False

    # 5. Trailing '_here', '-here', '_key', '-key' without digits
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



NON_SECRET_KEY_SUFFIXES = (
    "url", "base_url", "endpoint", "host", "port", "model", "name", "user", "username",
    "email", "org", "organization", "org_id", "version", "type", "mode", "path",
    "theme", "language", "lang", "format", "backend", "driver", "description",
    "profile", "agent", "system", "prompt"
)

SECRET_KEY_SUBSTRINGS = (
    "key", "token", "secret", "password", "passwd", "auth", "credential", "private"
)


def _is_valid_extracted_secret(key_name: str, value: str) -> bool:
    """Check if an extracted config value is genuinely a secret (and not a URL, model name, etc.)."""
    if not value or len(value) < 8 or not value.isascii():
        return False

    val_lower = value.lower()

    # 1. Reject URLs, endpoints, and file paths
    if any(val_lower.startswith(p) for p in ("http://", "https://", "ws://", "wss://", "/", "./", "../", "~/", "file://")):
        return False

    # 2. Known token signatures are always valid secrets
    if any(value.startswith(p) for p in (
        "sk-", "AKIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
        "AIza", "ya29.", "hf_", "SG.", "xox", "xapp-", "sk_live_", "rk_live_", "sk_test_", "rk_test_"
    )):
        return looks_like_secret(value)

    # 3. Check key name context
    k_parts = key_name.lower().replace("-", "_").split(".")
    last_k = k_parts[-1]

    # Explicitly reject non-secret field names
    if any(last_k == s or last_k.endswith(f"_{s}") for s in NON_SECRET_KEY_SUFFIXES):
        return False

    # Must have a secret-related key name
    if not any(sub in last_k for sub in SECRET_KEY_SUBSTRINGS):
        return False

    return looks_like_secret(value)


def _parse_yaml_fallback(content: str) -> Dict[str, Any]:
    """Lightweight pure-Python fallback YAML parser supporting nested mappings.

    Parses indentation-based nested YAML without requiring the external PyYAML package.
    Supports comments, quoted strings, nested dictionaries, and list items.
    """
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any]] = [(-1, root)]

    for raw_line in content.splitlines():
        line_no_comment = raw_line
        if "#" in raw_line:
            in_quote = False
            quote_char = ""
            comment_idx = -1
            for idx, ch in enumerate(raw_line):
                if ch in ('"', "'"):
                    if not in_quote:
                        in_quote = True
                        quote_char = ch
                    elif quote_char == ch:
                        in_quote = False
                elif ch == "#" and not in_quote:
                    comment_idx = idx
                    break
            if comment_idx != -1:
                line_no_comment = raw_line[:comment_idx]

        stripped = line_no_comment.strip()
        if not stripped:
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))

        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()

        current_container = stack[-1][1]

        # Check for list item "- key: value" or "- value"
        if stripped.startswith("- "):
            item_text = stripped[2:].strip()
            colon_pos = -1
            in_quote = False
            quote_char = ""
            for idx, ch in enumerate(item_text):
                if ch in ('"', "'"):
                    if not in_quote:
                        in_quote = True
                        quote_char = ch
                    elif quote_char == ch:
                        in_quote = False
                elif ch == ":" and not in_quote:
                    colon_pos = idx
                    break

            if colon_pos != -1:
                k = item_text[:colon_pos].strip().strip("\"'")
                v = item_text[colon_pos + 1:].strip()
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                item_dict = {k: v} if v else {}
                if isinstance(current_container, list):
                    current_container.append(item_dict)
                elif isinstance(current_container, dict):
                    current_container.setdefault("_items", []).append(item_dict)
                if not v:
                    stack.append((indent, item_dict))
            else:
                val = item_text.strip("\"'")
                if isinstance(current_container, list):
                    current_container.append(val)
                elif isinstance(current_container, dict):
                    current_container.setdefault("_items", []).append(val)
            continue

        # Check for key-value pair
        colon_pos = -1
        in_quote = False
        quote_char = ""
        for idx, ch in enumerate(stripped):
            if ch in ('"', "'"):
                if not in_quote:
                    in_quote = True
                    quote_char = ch
                elif quote_char == ch:
                    in_quote = False
            elif ch == ":" and not in_quote:
                colon_pos = idx
                break

        if colon_pos != -1:
            key = stripped[:colon_pos].strip().strip("\"'")
            val_part = stripped[colon_pos + 1:].strip()

            if not val_part:
                new_dict: Dict[str, Any] = {}
                if isinstance(current_container, dict):
                    current_container[key] = new_dict
                elif isinstance(current_container, list):
                    current_container.append({key: new_dict})
                stack.append((indent, new_dict))
            else:
                if (val_part.startswith('"') and val_part.endswith('"')) or (val_part.startswith("'") and val_part.endswith("'")):
                    val = val_part[1:-1]
                else:
                    val = val_part
                if isinstance(current_container, dict):
                    current_container[key] = val
                elif isinstance(current_container, list):
                    current_container.append({key: val})

    return root


def collect_known_secrets(scan_roots: List[Path]) -> List[Tuple[str, str, str]]:
    """Automatically collect real secret values from all profile .env and auth.json files.

    Returns: List of (secret_value, key_name, source_file_path)
    """
    collected = []
    seen_values = set()

    for root in scan_roots:
        if not root.exists():
            continue

        candidate_files = []
        if root.is_file():
            if is_intended_auth_file(root):
                candidate_files.append(root)
        elif root.is_dir():
            for f in root.rglob("*"):
                if f.is_file() and is_intended_auth_file(f):
                    candidate_files.append(f)


        for cf in candidate_files:
            try:
                def _extract_from_dict(d, prefix=""):
                    if isinstance(d, dict):
                        for k, v in d.items():
                            path_k = f"{prefix}.{k}" if prefix else str(k)
                            if isinstance(v, str):
                                v_clean = v.strip()
                                if _is_valid_extracted_secret(path_k, v_clean) and v_clean not in seen_values:
                                    seen_values.add(v_clean)
                                    collected.append((v_clean, path_k, str(cf)))
                            elif isinstance(v, (dict, list)):
                                _extract_from_dict(v, path_k)
                    elif isinstance(d, list):
                        for idx, item in enumerate(d):
                            _extract_from_dict(item, f"{prefix}[{idx}]")

                # 1. Parse JSON auth files
                if cf.suffix.lower() == ".json":
                    data = json.loads(cf.read_text(encoding="utf-8", errors="replace"))
                    _extract_from_dict(data)

                # 2. Parse YAML auth / config files
                elif cf.suffix.lower() in (".yaml", ".yml"):
                    content = cf.read_text(encoding="utf-8", errors="replace")
                    parsed_yaml = None
                    try:
                        import yaml
                        parsed_yaml = yaml.safe_load(content)
                    except Exception:
                        pass

                    if not isinstance(parsed_yaml, (dict, list)):
                        try:
                            parsed_yaml = _parse_yaml_fallback(content)
                        except Exception:
                            parsed_yaml = None

                    if isinstance(parsed_yaml, (dict, list)) and parsed_yaml:
                        _extract_from_dict(parsed_yaml)
                    else:
                        # Fallback line-based regex parser for YAML (no pyyaml dependency required)
                        for line in content.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            m = re.match(r"^([A-Za-z0-9_.-]+)\s*:\s*[\"']?([^\"'#\n]+)[\"']?", line)
                            if m:
                                k = m.group(1).strip()
                                v = m.group(2).strip()
                                if _is_valid_extracted_secret(k, v) and v not in seen_values:
                                    seen_values.add(v)
                                    collected.append((v, k, str(cf)))

                # 3. Parse .env files
                elif cf.suffix.lower() in (".env", "") or cf.name.startswith(".env"):
                    content = cf.read_text(encoding="utf-8", errors="replace")
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("export "):
                            line = line[7:].strip()
                        if "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("\"'")
                            if _is_valid_extracted_secret(k, v) and v not in seen_values:
                                seen_values.add(v)
                                collected.append((v, k, str(cf)))
            except Exception:
                pass


    return collected



def mask_secret(secret_str: str) -> str:
    """Mask secret keeping first 3 and last 3 chars."""
    if len(secret_str) <= 8:
        return "***"
    return f"{secret_str[:3]}...{secret_str[-3:]}"


class LeakDetector:
    def __init__(self, known_secrets: Optional[List[Tuple[str, str, str]]] = None):
        self.findings: List[Dict[str, Any]] = []
        self.known_secrets = known_secrets or []

    def scan_text(self, text: str, source_info: Dict[str, Any], with_line_numbers: bool = False) -> List[Dict[str, Any]]:
        """Scan string for leaks and return findings."""
        if not text or not isinstance(text, str):
            return []

        hits = []
        matched_spans: List[Tuple[int, int]] = []

        def _overlaps(start: int, end: int) -> bool:
            return any(max(start, s) < min(end, e) for s, e in matched_spans)

        def _make_source_info(pos: int) -> Dict[str, Any]:
            info = dict(source_info)
            if with_line_numbers:
                line_num = text[:pos].count("\n") + 1
                info["location"] = f"Line {line_num}"
            return info

        # 1. Exact Match against known secrets from profile .env / auth.json (Zero False Positives!)
        for secret_val, secret_name, auth_src in self.known_secrets:
            start = 0
            while True:
                pos = text.find(secret_val, start)
                if pos == -1:
                    break
                end = pos + len(secret_val)
                if not _overlaps(pos, end):
                    matched_spans.append((pos, end))
                    hits.append({
                        **_make_source_info(pos),
                        "type": f"Exact Match ({secret_name})",
                        "match": mask_secret(secret_val),
                        "raw_length": len(secret_val),
                        "raw_match": secret_val,
                        "secret_source": auth_src,
                    })
                start = end

        # 2. Regex direct signatures (genuine tokens/keys - do not subject to generic code expression heuristics)
        for label, pattern in PATTERNS:
            for match in pattern.finditer(text):
                val = match.group(0)
                if val != "***" and not val.startswith("***"):
                    start, end = match.span()
                    if not _overlaps(start, end):
                        matched_spans.append((start, end))
                        hits.append({
                            **_make_source_info(start),
                            "type": label,
                            "match": mask_secret(val),
                            "raw_length": len(val),
                            "raw_match": val,
                        })

        # 3. Key-Value pairs
        for match in SECRET_KEY_REGEX.finditer(text):
            val = match.group(2)
            if val != "***" and looks_like_secret(val):
                start, end = match.span(2)
                if not _overlaps(start, end):
                    matched_spans.append((start, end))
                    hits.append({
                        **_make_source_info(match.start()),
                        "type": f"KeyValue ({match.group(1)})",
                        "match": mask_secret(val),
                        "raw_length": len(val),
                        "raw_match": val,
                    })

        # 4. Natural Language
        for pat in NATURAL_LANG_REGEX:
            for match in pat.finditer(text):
                if len(match.groups()) >= 2:
                    val = match.group(2)
                    if val != "***" and looks_like_secret(val):
                        start, end = match.span(2)
                        if not _overlaps(start, end):
                            matched_spans.append((start, end))
                            hits.append({
                                **_make_source_info(match.start()),
                                "type": f"NaturalLanguage ({match.group(1)})",
                                "match": mask_secret(val),
                                "raw_length": len(val),
                                "raw_match": val,
                            })

        return hits

    def sanitize_text(self, text: str) -> str:
        """Sanitize text by replacing leaked credentials with ***."""
        if not text or not isinstance(text, str):
            return text

        result = text

        # 1. Exact replace known secrets first
        for secret_val, _, _ in self.known_secrets:
            result = result.replace(secret_val, "***")

        # 2. Direct patterns (scrub genuine token signatures)
        for _, pattern in PATTERNS:
            result = pattern.sub("***", result)

        # 3. Key-Value pairs
        def _replace_kv(m):
            val = m.group(2)
            if looks_like_secret(val):
                return m.group(0).replace(val, "***", 1)
            return m.group(0)

        result = SECRET_KEY_REGEX.sub(_replace_kv, result)

        # 4. Natural Language
        def _replace_nl(m):
            if len(m.groups()) >= 2:
                val = m.group(2)
                if val != "***" and looks_like_secret(val):
                    return m.group(0).replace(val, "***", 1)
            return m.group(0)

        for pat in NATURAL_LANG_REGEX:
            result = pat.sub(_replace_nl, result)

        return result






def scan_sqlite_db(db_path: Path, detector: LeakDetector, fix: bool = False) -> Tuple[int, int]:
    """Scan all text columns in all tables of a SQLite DB.

    Uses cursor streaming to minimize memory consumption on large tables,
    and wraps --fix modifications in strict transaction blocks with automatic rollback.
    """
    records_checked = 0
    leaks_found = 0
    conn = None

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

        modified_rows = []

        for table in tables:
            # Get table info (columns) with quoted table name
            cursor.execute(f'PRAGMA table_info("{table}");')
            cols_info = cursor.fetchall()

            # Get text/blob columns
            col_names = [c[1] for c in cols_info]
            if not col_names:
                continue

            # Check if rowid is supported (most tables), otherwise fallback to primary key column
            try:
                cursor.execute(f'SELECT rowid FROM "{table}" LIMIT 1;')
                cursor.fetchone()
                pk_select = "rowid"
            except Exception:
                pk_col = next((c[1] for c in cols_info if c[5] > 0), col_names[0])
                pk_select = f'"{pk_col}"'

            query_cols = ", ".join(f'"{c}"' for c in col_names)
            cursor.execute(f'SELECT {pk_select}, {query_cols} FROM "{table}";')

            # Stream rows one by one to avoid large memory footprint on massive tables
            for row in cursor:
                records_checked += 1
                row_id = row[0]
                row_data = row[1:]

                row_needs_update = False
                updated_col_values = {}

                for col_idx, col_name in enumerate(col_names):
                    val = row_data[col_idx]
                    if isinstance(val, str):
                        hits = detector.scan_text(val, {
                            "source_file": str(db_path),
                            "location": f"Table: {table} | Row ID: {row_id} | Column: {col_name}",
                        })
                        if hits:
                            detector.findings.extend(hits)
                            leaks_found += len(hits)
                            if fix:
                                sanitized_val = detector.sanitize_text(val)
                                if sanitized_val != val:
                                    row_needs_update = True
                                    updated_col_values[col_name] = sanitized_val

                if fix and row_needs_update:
                    modified_rows.append((table, pk_select, row_id, updated_col_values))

        # Apply fixes if requested
        if fix and modified_rows:
            # Create backup before modification
            backup_path = db_path.with_suffix(f"{db_path.suffix}.bak")
            shutil.copy2(db_path, backup_path)
            print(f"  💾 Backup created: {backup_path}")

            try:
                with conn:
                    for table, pk_sel, row_id, updates in modified_rows:
                        set_clause = ", ".join(f'"{k}" = ?' for k in updates.keys())
                        values = list(updates.values()) + [row_id]
                        cursor.execute(f'UPDATE "{table}" SET {set_clause} WHERE {pk_sel} = ?;', values)
                print(f"  ✨ Redacted & updated {len(modified_rows)} row(s) in {db_path.name}")
            except Exception as update_err:
                conn.rollback()
                print(
                    f"  ⚠️ Failed to update SQLite DB {db_path} (changes rolled back, backup available at {backup_path.name}): {update_err}",
                    file=sys.stderr,
                )
                raise
    except Exception as e:
        print(f"  ⚠️ Error reading/updating SQLite DB {db_path}: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()

    return records_checked, leaks_found


def scan_json_or_text_file(file_path: Path, detector: LeakDetector) -> Tuple[int, int]:
    """Scan plain text, JSON, or JSONL files for credential leaks (including multiline secrets)."""
    records_checked = 0
    leaks_found = 0

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        records_checked = len(content.splitlines()) or (1 if content else 0)

        hits = detector.scan_text(
            content,
            {"source_file": str(file_path)},
            with_line_numbers=True
        )
        if hits:
            detector.findings.extend(hits)
            leaks_found = len(hits)
    except Exception as e:
        print(f"  ⚠️ Error reading file {file_path}: {e}", file=sys.stderr)

    return records_checked, leaks_found


def main():
    parser = argparse.ArgumentParser(
        description="Audit Hermes conversation DBs and log files for credential leaks."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to scan (defaults to ~/.hermes/ and current directory)",
    )
    parser.add_argument(
        "--fix",
        "--redact",
        action="store_true",
        help="Automatically redact detected credentials in SQLite databases (creates .bak backup)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings in JSON format",
    )

    args = parser.parse_args()

    # Determine paths to scan
    target_paths = []
    if args.paths:
        for p in args.paths:
            target_paths.append(Path(p).expanduser().resolve())
    else:
        # Default scan locations
        hermes_home = Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser().resolve()
        if hermes_home.exists():
            target_paths.append(hermes_home)
        target_paths.append(Path.cwd())

    # Deduplicate paths
    target_paths = list(dict.fromkeys(target_paths))

    # Auto-collect real secrets from all profiles (.env, auth.json, etc.)
    known_secrets = collect_known_secrets(target_paths)
    detector = LeakDetector(known_secrets=known_secrets)
    total_records = 0
    scanned_files = 0

    if not args.json:
        print("🔍 Scanning for credential leaks...")
        for p in target_paths:
            print(f"  • Target: {p}")
        if known_secrets:
            print(f"  🔑 Loaded {len(known_secrets)} authentic secret(s) from profile configs for exact-match tracking")
        print()


    for target in target_paths:
        if target.is_file():
            files_to_scan = [target]
        elif target.is_dir():
            files_to_scan = [
                f for f in target.rglob("*")
                if f.is_file() and not any(part.startswith(".") and part != ".hermes" for part in f.parts)
            ]
        else:
            continue

        for file_path in files_to_scan:
            # Skip ignored directories and binary files
            if any(p in file_path.parts for p in IGNORE_DIRS):
                continue

            # Skip legitimate auth configuration files during directory scanning
            if target.is_dir() and is_intended_auth_file(file_path):
                continue


            # Skip static repository/plugin documentation files (README.md, LICENSE, etc.) during directory scanning
            if target.is_dir() and file_path.name.lower() in ("readme.md", "license", "changelog.md", "contributing.md"):
                continue



            # Skip files larger than 10MB to avoid scanning huge binaries/dumps
            try:
                if file_path.stat().st_size > 10 * 1024 * 1024:
                    continue
            except Exception:
                continue

            suffix = file_path.suffix.lower()
            name_lower = file_path.name.lower()

            if suffix in (".db", ".sqlite", ".sqlite3"):
                scanned_files += 1
                rec, _ = scan_sqlite_db(file_path, detector, fix=args.fix)
                total_records += rec
            elif (
                suffix in (
                    ".json", ".jsonl", ".txt", ".log", ".md", ".yaml", ".yml",
                    ".toml", ".ini", ".conf", ".cfg", ".sh", ".bash", ".zsh", ".env"
                )
                or name_lower.startswith(".env")
            ):
                scanned_files += 1
                rec, _ = scan_json_or_text_file(file_path, detector)
                total_records += rec



    # Output results

    if args.json:
        output = {
            "scanned_files": scanned_files,
            "total_records_checked": total_records,
            "total_leaks_found": len(detector.findings),
            "findings": detector.findings,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return

    # CLI Output formatting
    print("-" * 70)
    if detector.findings:
        print(f"🚨 FOUND {len(detector.findings)} POTENTIAL CREDENTIAL LEAK(S):")
        print("-" * 70)
        for idx, f in enumerate(detector.findings, start=1):
            print(f"[{idx}] Type: \033[91m{f['type']}\033[0m")
            print(f"    File:     {f['source_file']}")
            print(f"    Location: {f['location']}")
            print(f"    Match:    \033[93m{f['match']}\033[0m (length: {f['raw_length']})")
            print()

        if args.fix:
            print("✅ All findings in SQLite DBs have been redacted and backed up.")
        else:
            print("💡 Tip: Run with `--fix` to automatically redact credentials in SQLite DBs.")
    else:
        print("✅ No credential leaks found! All scanned databases and logs are clean.")
    print("-" * 70)
    print(f"Summary: Checked {scanned_files} file(s) across {total_records} record/line entries.\n")


if __name__ == "__main__":
    main()
