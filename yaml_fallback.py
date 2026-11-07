"""Dependency-free YAML reading for the credential scanner.

PyYAML is optional in the environments this plugin runs in (it is absent from the
Hermes runtime Python), so the scanner needs a parser of its own. This module holds
only pure functions: no I/O, no config knowledge, no logging, which keeps the
fallback testable in isolation and off the scanner main path.

Scope: the indentation-based subset Hermes config/auth files actually use, plus
block scalars (|, >), multi-document files (---), flow mappings ({a: 1}), JSON
documents, sequences of mappings, and quoted values. Out-of-scope constructs are
reported by raising ValueError with a line number, which the caller turns into a
scan error.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple


def _split_top_level_colon(text: str) -> int:
    """Index of the first ``:`` that is followed by space/EOL and sits outside quotes."""
    in_quote = False
    quote_char = ""
    for idx, ch in enumerate(text):
        if ch in ('"', "'"):
            if not in_quote:
                in_quote, quote_char = True, ch
            elif quote_char == ch:
                in_quote = False
        elif ch == ":" and not in_quote:
            if idx + 1 == len(text) or text[idx + 1] in (" ", "\t"):
                return idx
    return -1


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def _parse_flow_map(text: str) -> Dict[str, Any]:
    """Parse a shallow flow mapping (``{a: 1, b: "x"}``) without a YAML dependency."""
    body = text.strip()
    if body.startswith("{"):
        body = body[1:]
    if body.endswith("}"):
        body = body[:-1]
    out: Dict[str, Any] = {}
    part: List[str] = []
    in_quote = False
    quote_char = ""
    parts: List[str] = []
    for ch in body:
        if ch in ('"', "'"):
            if not in_quote:
                in_quote, quote_char = True, ch
            elif quote_char == ch:
                in_quote = False
        elif ch == "," and not in_quote:
            parts.append("".join(part))
            part = []
            continue
        part.append(ch)
    parts.append("".join(part))
    for entry in parts:
        if not entry.strip():
            continue
        idx = _split_top_level_colon(entry)
        if idx == -1:
            continue
        out[_strip_quotes(entry[:idx].strip())] = _strip_quotes(entry[idx + 1:].strip())
    return out


def _ensure_sequence_container(stack, container) -> List[Any]:
    """Return ``container`` as a list, converting a pending empty ``key:`` mapping in place.

    A key with no value may still turn out to be a sequence (``keys:\\n  - a``); the parent
    slot is rewritten so the children are not silently dropped.
    """
    if isinstance(container, list):
        return container
    if isinstance(container, dict) and len(stack) >= 2:
        parent = stack[-2][1]
        key = stack[-1][2]
        if isinstance(parent, dict) and key is not None:
            seq: List[Any] = []
            parent[key] = seq
            stack[-1] = (stack[-1][0], seq, key)
            return seq
    return container


def parse_yaml(content: str) -> Dict[str, Any]:
    """Lightweight pure-Python fallback YAML parser supporting nested mappings with syntax validation.

    Parses indentation-based nested YAML without requiring the external PyYAML package.
    Supports comments, quoted strings, nested dictionaries, and list items.
    Validates indentation hierarchy, bracket matching, quotes, and forbidden tabs.
    """
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Any, Optional[str]]] = [(-1, root, None)]
    expecting_indent_after: Optional[Tuple[int, str, int]] = None
    # (indent, container, key, collected_lines, style) while a |/> block scalar body is open.
    block_state: Optional[Tuple[int, Any, str, List[str], str]] = None

    stripped_doc = content.strip()
    if stripped_doc.startswith("{"):
        # JSON is valid YAML; try the real parser first, then the shallow flow reader.
        try:
            parsed_json = json.loads(stripped_doc)
            if isinstance(parsed_json, dict):
                return parsed_json
        except (ValueError, TypeError):
            pass
        return _parse_flow_map(stripped_doc)

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        # 0. Block scalar (| or >) body: every more-indented line belongs to the value,
        #    including blank lines and tab characters that would be illegal as indentation.
        if block_state is not None:
            b_indent, b_container, b_key, b_lines, b_style = block_state
            body_indent = len(raw_line) - len(raw_line.lstrip(" "))
            if not raw_line.strip() or body_indent > b_indent:
                b_lines.append(raw_line[b_indent + 1:] if len(raw_line) > b_indent + 1 else "")
                continue
            joiner = " " if b_style == ">" else "\n"
            b_container[b_key] = joiner.join(
                l.strip() for l in b_lines) if b_style == ">" else joiner.join(b_lines).strip()
            block_state = None

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

        # YAML document markers: a multi-document file is still one secret-bearing file.
        if stripped in ("---", "..."):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))

        # 2. A mapping key without a value is a valid null; a dedented sibling must not raise.
        if expecting_indent_after is not None:
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
            seq = _ensure_sequence_container(stack, current_container)
            item_text = stripped[2:].strip()
            colon_pos = _split_top_level_colon(item_text)

            if colon_pos != -1:
                k = _strip_quotes(item_text[:colon_pos].strip())
                v = item_text[colon_pos + 1:].strip()
                if (v.startswith('"') and not v.endswith('"')) or (v.startswith("'") and not v.endswith("'")):
                    raise ValueError(f"Line {line_num}: Unclosed quotes in YAML list value")
                v = _strip_quotes(v)
                item_dict: Dict[str, Any] = {}
                if v:
                    item_dict[k] = v
                else:
                    item_dict[k] = {}
                seq.append(item_dict)
                # Keep the item mapping on the stack so deeper sibling keys join THIS item
                # (previously they overwrote the pending mapping and lost earlier items).
                stack.append((indent, item_dict, None))
                if not v:
                    stack.append((indent + 1, item_dict[k], k))
            else:
                seq.append(_strip_quotes(item_text))
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
                # Block scalar: | keeps newlines, > folds them; the body is consumed above.
                if isinstance(current_container, dict) and re.fullmatch(r"[|>][+-]?", val_part):
                    current_container[key] = ""
                    block_state = (indent, current_container, key, [], val_part[0])
                    continue
                # Flow mapping: {a: 1, b: "x"}
                if val_part.startswith("{") and val_part.endswith("}"):
                    parsed_flow = _parse_flow_map(val_part)
                    if isinstance(current_container, dict):
                        current_container[key] = parsed_flow
                    elif isinstance(current_container, list):
                        current_container.append({key: parsed_flow})
                    continue
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

    # Flush a block scalar that ran to end of file.
    if block_state is not None:
        b_indent, b_container, b_key, b_lines, b_style = block_state
        b_container[b_key] = (" ".join(l.strip() for l in b_lines) if b_style == ">"
                              else "\n".join(b_lines).strip())

    return root
