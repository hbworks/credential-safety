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
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try importing patterns and hooks from package, current directory, or script directory
try:
    from . import patterns, hooks
except (ImportError, ValueError):
    try:
        import patterns
        import hooks
    except ImportError:
        script_dir = str(Path(__file__).resolve().parent)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import patterns
        import hooks

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





# Key-Value credential pattern (synchronized with hooks._SECRET_KEY_REGEX)
SECRET_KEY_REGEX = re.compile(
    rf"[\"']?(?<![a-zA-Z0-9_])({hooks._SECRET_KEY_REGEX})(?![a-zA-Z0-9_])[\"']?\s*[:=]\s*[\"']?([^'\"\s\n,}}\)\];>]+)[\"']?",
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




# Re-export and delegate directly to hooks for single source of truth (DRY)
looks_like_secret = hooks._looks_like_secret
_shannon_entropy = hooks._shannon_entropy
_is_placeholder = hooks._is_placeholder
_should_mask_value = getattr(hooks, "_should_mask_value", lambda k, v: looks_like_secret(v))
_is_sensitive_key = getattr(hooks, "_is_sensitive_key", lambda k: False)
PLACEHOLDER_PREFIXES = hooks.PLACEHOLDER_PREFIXES
PLACEHOLDER_KEYWORDS = hooks.PLACEHOLDER_KEYWORDS



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
    """Lightweight pure-Python fallback YAML parser supporting nested mappings with syntax validation.

    Parses indentation-based nested YAML without requiring the external PyYAML package.
    Supports comments, quoted strings, nested dictionaries, and list items.
    Validates indentation hierarchy, bracket matching, quotes, and forbidden tabs.
    """
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any, Optional[str]]] = [(-1, root, None)]
    expecting_indent_after: Optional[Tuple[int, str, int]] = None

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        # 1. Reject tab characters in indentation
        leading_spaces = len(raw_line) - len(raw_line.lstrip(" "))
        if "\t" in raw_line[:leading_spaces + 1]:
            raise ValueError(f"Line {line_num}: Tab characters are forbidden in YAML indentation")

        # Strip comments outside quotes
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

        # 2. Check if this line satisfies required indent from preceding mapping key without value
        if expecting_indent_after is not None:
            parent_indent, parent_key, parent_line = expecting_indent_after
            if indent <= parent_indent:
                raise ValueError(
                    f"Line {line_num}: Bad indentation after mapping key (line {parent_line}); "
                    f"expected indent > {parent_indent}, found {indent}"
                )
            expecting_indent_after = None

        # 3. Check for unclosed brackets or braces in line (only outside quotes)
        in_q = False
        q_c = ""
        open_b = 0
        open_c = 0
        for ch in stripped:
            if ch in ('"', "'"):
                if not in_q:
                    in_q = True
                    q_c = ch
                elif q_c == ch:
                    in_q = False
            elif not in_q:
                if ch == "[":
                    open_b += 1
                elif ch == "]":
                    open_b -= 1
                elif ch == "{":
                    open_c += 1
                elif ch == "}":
                    open_c -= 1

        if open_b != 0 or open_c != 0:
            raise ValueError(f"Line {line_num}: Unclosed brackets or braces in YAML")

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
                    if idx + 1 == len(item_text) or item_text[idx + 1] in (" ", "\t"):
                        colon_pos = idx
                        break

            if colon_pos != -1:
                k = item_text[:colon_pos].strip().strip("\"'")
                v = item_text[colon_pos + 1:].strip()
                if (v.startswith('"') and not v.endswith('"')) or (v.startswith("'") and not v.endswith("'")) or (len(v) == 1 and v in ('"', "'")):
                    raise ValueError(f"Line {line_num}: Unclosed quotes in YAML list value")
                if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                item_dict = {k: v} if v else {}
                if isinstance(current_container, list):
                    current_container.append(item_dict)
                elif isinstance(current_container, dict):
                    current_container.setdefault("_items", []).append(item_dict)
                if not v:
                    stack.append((indent, item_dict, k))
                    expecting_indent_after = (indent, k, line_num)
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
                if idx + 1 == len(stripped) or stripped[idx + 1] in (" ", "\t"):
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
                stack.append((indent, new_dict, key))
                expecting_indent_after = (indent, key, line_num)
            else:
                if (val_part.startswith('"') and not val_part.endswith('"')) or (val_part.startswith("'") and not val_part.endswith("'")) or (len(val_part) == 1 and val_part in ('"', "'")):
                    raise ValueError(f"Line {line_num}: Unclosed quotes in YAML value")
                if (val_part.startswith('"') and val_part.endswith('"')) or (val_part.startswith("'") and val_part.endswith("'")):
                    val = val_part[1:-1]
                else:
                    val = val_part
                if isinstance(current_container, dict):
                    current_container[key] = val
                elif isinstance(current_container, list):
                    current_container.append({key: val})
        else:
            raise ValueError(f"Line {line_num}: Invalid YAML syntax (missing colon or unrecognized item)")

    return root


def collect_known_secrets(scan_roots: List[Path], errors: Optional[List[str]] = None) -> List[Tuple[str, str, str]]:
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
                    has_pyyaml = False
                    try:
                        import yaml
                        has_pyyaml = (yaml is not None)
                    except ImportError:
                        has_pyyaml = False

                    if has_pyyaml:
                        # Strictly validate YAML syntax with PyYAML
                        parsed_yaml = yaml.safe_load(content)
                        if isinstance(parsed_yaml, (dict, list)) and parsed_yaml:
                            _extract_from_dict(parsed_yaml)
                    else:
                        # Fallback for environments without PyYAML: strictly validate with pure-Python parser
                        parsed_yaml = _parse_yaml_fallback(content)
                        if isinstance(parsed_yaml, (dict, list)) and parsed_yaml:
                            _extract_from_dict(parsed_yaml)

                # 3. Parse .env files
                elif cf.suffix.lower() in (".env", "") or cf.name.startswith(".env"):
                    content = cf.read_text(encoding="utf-8", errors="replace")
                    invalid_lines = []
                    for line_num, raw_line in enumerate(content.splitlines(), start=1):
                        line = raw_line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("export "):
                            line = line[7:].strip()

                        # 1. Missing '='
                        if "=" not in line:
                            invalid_lines.append(f"Line {line_num}: missing '='")
                            continue

                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip()

                        # 2. Empty key
                        if not k:
                            invalid_lines.append(f"Line {line_num}: empty key name")
                            continue

                        # 3. Invalid characters in key name
                        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", k):
                            invalid_lines.append(f"Line {line_num}: invalid key name")
                            continue

                        # 4. Unclosed quotes in value
                        if (v.startswith('"') and not v.endswith('"')) or (v.startswith("'") and not v.endswith("'")) or (len(v) == 1 and v in ('"', "'")):
                            invalid_lines.append(f"Line {line_num}: unclosed quote in value")
                            continue

                        # 5. Broken continuation line
                        if v.endswith("\\"):
                            invalid_lines.append(f"Line {line_num}: broken continuation line")
                            continue

                        v_clean = v.strip("\"'")
                        if _is_valid_extracted_secret(k, v_clean) and v_clean not in seen_values:
                            seen_values.add(v_clean)
                            collected.append((v_clean, k, str(cf)))

                    if invalid_lines:
                        raise ValueError(f"Malformed .env file: {'; '.join(invalid_lines[:3])}")
            except Exception as e:
                clean_err = _clean_parse_error(e)
                err_msg = f"Failed to parse authentic config file {cf}: {clean_err}"
                if errors is not None:
                    errors.append(err_msg)
                print(f"  ⚠️ {err_msg}", file=sys.stderr)


    return collected


def _clean_parse_error(e: Exception) -> str:
    """Format parser errors safely without echoing raw file snippets or leaked secrets."""
    # PyYAML errors (MarkedYAMLError) include source snippets in str(e).
    # Safely extract line, column, and error description without echoing line content.
    if hasattr(e, "problem"):
        mark = getattr(e, "problem_mark", None)
        context = getattr(e, "context", None)
        problem = getattr(e, "problem", "syntax error")
        loc = f"line {mark.line + 1}, column {mark.column + 1}" if mark else "unknown location"
        ctx_desc = f" ({context})" if context else ""
        return f"YAML error near {loc}: {problem}{ctx_desc}"

    # General exceptions: keep only the first line to avoid multiline code dumps
    msg = str(e)
    return msg.splitlines()[0] if msg else "Unknown error"



def mask_secret(secret_str: str) -> str:
    """Mask secret completely as ***.

    Ensures absolute zero secret leakage: no partial prefix or suffix fragments
    are ever emitted into audit findings or CLI output.
    """
    return "***"


class LeakDetector:
    def __init__(self, known_secrets: Optional[List[Tuple[str, str, str]]] = None):
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.known_secrets = known_secrets or []

    def record_error(self, err_msg: str) -> None:
        """Record an error encountered during scanning."""
        self.errors.append(err_msg)

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
                        })

        # 3. Key-Value pairs
        for match in SECRET_KEY_REGEX.finditer(text):
            key_name = match.group(1)
            val = match.group(2)
            if val != "***" and _should_mask_value(key_name, val):
                start, end = match.span(2)
                if not _overlaps(start, end):
                    matched_spans.append((start, end))
                    hits.append({
                        **_make_source_info(match.start()),
                        "type": f"KeyValue ({key_name})",
                        "match": mask_secret(val),
                        "raw_length": len(val),
                    })

        # 4. Natural Language
        for pat in NATURAL_LANG_REGEX:
            for match in pat.finditer(text):
                if len(match.groups()) >= 2:
                    key_name = match.group(1)
                    val = match.group(2)
                    if val != "***" and _should_mask_value(key_name, val):
                        start, end = match.span(2)
                        if not _overlaps(start, end):
                            matched_spans.append((start, end))
                            hits.append({
                                **_make_source_info(match.start()),
                                "type": f"NaturalLanguage ({key_name})",
                                "match": mask_secret(val),
                                "raw_length": len(val),
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
            key_name = m.group(1)
            val = m.group(2)
            if _should_mask_value(key_name, val):
                return m.group(0).replace(val, "***", 1)
            return m.group(0)

        result = SECRET_KEY_REGEX.sub(_replace_kv, result)

        # 4. Natural Language
        def _replace_nl(m):
            if len(m.groups()) >= 2:
                key_name = m.group(1)
                val = m.group(2)
                if _should_mask_value(key_name, val):
                    return m.group(0).replace(val, "***", 1)
            return m.group(0)

        for pat in NATURAL_LANG_REGEX:
            result = pat.sub(_replace_nl, result)

        return result


def _quote_ident(name: str) -> str:
    """Safely quote a SQLite table or column identifier."""
    return '"' + name.replace('"', '""') + '"'


def _atomic_create_backup(src_path: Path) -> Path:
    """Atomically create a unique backup copy of src_path without TOCTOU race conditions.

    Uses OS-level atomic creation (O_CREAT | O_EXCL) so that multiple concurrent processes
    cannot collide or overwrite each other's backups.
    """
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    def _try_atomic_copy(dest: Path) -> bool:
        try:
            fd = os.open(str(dest), flags, 0o600)
        except FileExistsError:
            return False

        try:
            with open(fd, "wb", closefd=True) as f_out, open(src_path, "rb") as f_in:
                shutil.copyfileobj(f_in, f_out)
            shutil.copystat(src_path, dest)
            return True
        except Exception:
            try:
                dest.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    # 1. Try standard backup (e.g. data.sqlite.bak)
    primary_bak = src_path.with_suffix(f"{src_path.suffix}.bak")
    if _try_atomic_copy(primary_bak):
        return primary_bak

    # 2. Try timestamped backup (e.g. data.sqlite.bak.20260913_013000)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = src_path.with_name(f"{src_path.name}.bak.{timestamp}")
    if _try_atomic_copy(candidate):
        return candidate

    # 3. Try incremented counter backups (e.g. data.sqlite.bak.20260913_013000_1)
    counter = 1
    while True:
        candidate = src_path.with_name(f"{src_path.name}.bak.{timestamp}_{counter}")
        if _try_atomic_copy(candidate):
            return candidate
        counter += 1


def scan_sqlite_db(db_path: Path, detector: LeakDetector, fix: bool = False) -> Tuple[int, int]:
    """Scan a SQLite database for credentials and optionally redact them in-place."""
    if not db_path.exists():
        err_msg = f"Database file not found: {db_path}"
        detector.record_error(err_msg)
        print(f"  ⚠️ {err_msg}", file=sys.stderr)
        return 0, 0

    conn = None
    records_checked = 0
    leaks_found = 0

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

        modified_rows = []

        for table in tables:
            tbl_quoted = _quote_ident(table)
            # Get table info (columns) with quoted table name
            cursor.execute(f'PRAGMA table_info({tbl_quoted});')
            cols_info = cursor.fetchall()

            # Get text/blob columns
            col_names = [c[1] for c in cols_info]
            if not col_names:
                continue

            # Check if rowid is supported (most tables), otherwise fallback to primary key column
            try:
                cursor.execute(f'SELECT rowid FROM {tbl_quoted} LIMIT 1;')
                cursor.fetchone()
                pk_select = "rowid"
            except Exception:
                pk_col = next((c[1] for c in cols_info if c[5] > 0), col_names[0])
                pk_select = _quote_ident(pk_col)

            query_cols = ", ".join(_quote_ident(c) for c in col_names)
            cursor.execute(f'SELECT {pk_select}, {query_cols} FROM {tbl_quoted};')

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
                            "column": col_name,
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
            # Create backup atomically before modification (eliminates TOCTOU race conditions)
            backup_path = _atomic_create_backup(db_path)
            print(f"  💾 Backup created: {backup_path}")

            try:
                with conn:
                    for table, pk_sel, row_id, updates in modified_rows:
                        tbl_q = _quote_ident(table)
                        set_clause = ", ".join(f'{_quote_ident(k)} = ?' for k in updates.keys())
                        values = list(updates.values()) + [row_id]
                        cursor.execute(f'UPDATE {tbl_q} SET {set_clause} WHERE {pk_sel} = ?;', values)
                print(f"  ✨ Redacted & updated {len(modified_rows)} row(s) in {db_path.name}")
            except Exception as update_err:
                conn.rollback()
                print(
                    f"  ⚠️ Failed to update SQLite DB {db_path} (changes rolled back, backup available at {backup_path.name}): {update_err}",
                    file=sys.stderr,
                )
                raise
    except Exception as e:
        err_msg = f"Error reading/updating SQLite DB {db_path}: {e}"
        detector.record_error(err_msg)
        print(f"  ⚠️ {err_msg}", file=sys.stderr)
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
        err_msg = f"Error reading file {file_path}: {e}"
        detector.record_error(err_msg)
        print(f"  ⚠️ {err_msg}", file=sys.stderr)

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
    missing_paths = []
    if args.paths:
        for p in args.paths:
            target_p = Path(p).expanduser().resolve()
            if not target_p.exists():
                missing_paths.append(p)
            else:
                target_paths.append(target_p)
    else:
        # Default scan locations
        hermes_home = Path(os.environ.get("HERMES_HOME", "~/.hermes")).expanduser().resolve()
        if hermes_home.exists():
            target_paths.append(hermes_home)
        target_paths.append(Path.cwd())

    # Deduplicate paths
    target_paths = list(dict.fromkeys(target_paths))

    detector = LeakDetector()
    total_records = 0
    scanned_files = 0

    for p in missing_paths:
        err_msg = f"Target path does not exist: {p}"
        detector.record_error(err_msg)
        print(f"  ⚠️ {err_msg}", file=sys.stderr)

    # Auto-collect real secrets from all profiles (.env, auth.json, etc.)
    known_secrets = collect_known_secrets(target_paths, errors=detector.errors)
    detector.known_secrets = known_secrets

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
            "scan_errors": len(detector.errors),
            "findings": detector.findings,
            "errors": detector.errors,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        if detector.errors:
            sys.exit(2)
        elif detector.findings:
            sys.exit(1)
        else:
            sys.exit(0)

    # CLI Output formatting
    print("-" * 70)
    if detector.errors:
        print(f"⚠️ ENCOUNTERED {len(detector.errors)} SCAN ERROR(S):")
        for idx, err in enumerate(detector.errors, start=1):
            print(f"  [{idx}] {err}")
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
    elif not detector.errors:
        print("✅ No credential leaks found! All scanned databases and logs are clean.")
    else:
        print("⚠️ Scan completed with errors. Cleanliness cannot be guaranteed.")
    print("-" * 70)
    print(f"Summary: Checked {scanned_files} file(s) across {total_records} record/line entries.\n")

    if detector.errors:
        sys.exit(2)
    elif detector.findings:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
