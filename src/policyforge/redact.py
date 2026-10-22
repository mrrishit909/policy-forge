"""Second-layer redaction. The adapters already drop sensitive raw fields; this catches whatever slips through and
records what was removed by path, never by value. The same rules redact raw-file excerpts, decide which raw lines a
published diff may not touch, and detect leaks in any output text.

A value is sensitive when:
  - any member name on its path is sensitive (policy/sensitive-names.json documents the word rule), whatever the
    value's type (strings, numbers, booleans and null are all masked);
  - it sits under a Value/Values member whose sibling Key/Name member holds a sensitive name (tag and parameter
    lists such as {"Key": "db_password", "Value": "..."});
  - it is a string that matches a credential pattern; or
  - it is a string holding JSON text in which any of these rules finds a sensitive value (checked recursively).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from policyforge.jsonpos import Scan, Token, escape

_VOCAB = json.loads((Path(__file__).resolve().parents[2] / "policy" / "sensitive-names.json").read_text())[
    "sensitive_names"]
WORDS = frozenset(_VOCAB["words"])
PAIRS = frozenset(_VOCAB["pairs"])
NAME_MEMBERS = frozenset(_VOCAB["name_members"])
VALUE_MEMBERS = frozenset(_VOCAB["value_members"])
SENSITIVE_VALUE = re.compile(
    r"pf-canary-[0-9a-f]+-not-a-secret"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|(?i:\b(?:password|pwd|accountkey|sharedaccesskey)=[^;\s\"]+)"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\bsk-[A-Za-z0-9_-]{20,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}"
    r"|\bxox[abposr]-[A-Za-z0-9-]{10,}"
)
MASK = "[redacted]"
MIN_KNOWN = 5  # shorter values are protected by position (excerpts, diff context), not by substring search
_MAX_DEPTH = 4


def key_words(name: str) -> list[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"([A-Za-z])([0-9])", r"\1_\2", s)
    s = s.encode("utf-8").lower().decode("utf-8")  # ASCII case folding only, as in the adapters
    return [w for w in re.split(r"[^a-z0-9]+", s) if w and not re.fullmatch(r"[0-9]+", w)]


def sensitive_name(name: Any) -> bool:
    if not isinstance(name, str):
        return False
    w = key_words(name)
    return bool(w) and (w[-1] in WORDS or "_".join(w[-2:]) in PAIRS)


def _json_like(value: str) -> bool:
    s = value.strip()
    return len(s) > 1 and s[0] + s[-1] in ("{}", "[]")


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def tree_secrets(node: Any, depth: int = 0) -> list[Any]:
    """Every sensitive scalar inside a parsed JSON tree, by the module rules (empty list: nothing sensitive)."""
    found: list[Any] = []

    def walk(n: Any, hot: bool) -> None:
        if isinstance(n, dict):
            hot_values: set[str] = set()
            name_key = next((k for k in n if k.lower() in NAME_MEMBERS), None)
            if name_key is not None and sensitive_name(n[name_key]):
                hot_values = {k for k in n if k.lower() in VALUE_MEMBERS}
            for k, v in n.items():
                walk(v, hot or sensitive_name(k) or k in hot_values)
        elif isinstance(n, list):
            for v in n:
                walk(v, hot)
        elif hot:
            found.append(n)
        elif isinstance(n, str):
            found.extend(m.group(0) for m in SENSITIVE_VALUE.finditer(n))
            found.extend(json_secrets(n, depth + 1))

    walk(node, False)
    return found


def json_secrets(value: str, depth: int = 0) -> list[Any]:
    """Sensitive values inside a string that holds JSON text (empty when it is not JSON or holds nothing)."""
    if depth > _MAX_DEPTH or not _json_like(value):
        return []
    try:
        parsed = json.loads(value)
    except ValueError:
        return []
    return tree_secrets(parsed, depth)


def _known(values: list[Any]) -> set[str]:
    return {_text(v) for v in values if not isinstance(v, bool) and v is not None and len(_text(v)) >= MIN_KNOWN}


# ------------------------------------------------------------------ parsed trees (normalized properties)
def redact_tree(obj: Any, path: str = "") -> tuple[Any, list[dict[str, str]]]:
    """Drop members with sensitive names (and Value members of sensitive Key/Name pairs) and mask strings that are
    credential-like or hold JSON with sensitive content. Returns (clean copy, records by path)."""
    records: list[dict[str, str]] = []

    def walk(node: Any, at: str) -> Any:
        if isinstance(node, dict):
            name_key = next((k for k in node if k.lower() in NAME_MEMBERS), None)
            hot_values = ({k for k in node if k.lower() in VALUE_MEMBERS}
                          if name_key is not None and sensitive_name(node[name_key]) else set())
            out = {}
            for key, value in node.items():
                sub = f"{at}/{escape(key)}"
                if sensitive_name(key) or key in hot_values:
                    records.append({"path": sub, "reason": "sensitive-name", "action": "dropped"})
                    continue
                out[key] = walk(value, sub)
            return out
        if isinstance(node, list):
            return [walk(v, f"{at}/{i}") for i, v in enumerate(node)]
        if isinstance(node, str) and (SENSITIVE_VALUE.search(node) or json_secrets(node)):
            records.append({"path": at, "reason": "sensitive-value", "action": "masked"})
            return MASK
        return node

    return walk(obj, path), records


# ------------------------------------------------------------------ raw text (excerpts, diff guard, leak checks)
@dataclass(frozen=True)
class Analysis:
    masked: tuple[Token, ...]  # tokens to replace with "[redacted]" in any published raw text
    known: frozenset[str]  # values to search for in outputs (direct secrets of MIN_KNOWN+ characters)
    lines: frozenset[int]  # 1-based raw lines holding a masked token


def _last_key(path: tuple[str | int, ...]) -> str | None:
    return next((p for p in reversed(path) if isinstance(p, str)), None)


def analyse(scan: Scan) -> Analysis:
    cached = scan.__dict__.get("_redaction")
    if cached is not None:
        return cached
    hot_prefixes: list[tuple[str | int, ...]] = []
    for opath, keys in scan.members.items():
        name_key = next((k for k in keys if k.lower() in NAME_MEMBERS), None)
        tok = scan.scalars.get(opath + (name_key,)) if name_key is not None else None
        if tok is not None and tok.kind == "string" and sensitive_name(tok.value):
            hot_prefixes += [opath + (k,) for k in keys if k.lower() in VALUE_MEMBERS]
    masked, known = [], set()
    for tok in scan.tokens:
        sibling = any(tok.path[: len(q)] == q for q in hot_prefixes)
        direct = sibling or sensitive_name(_last_key(tok.path))
        inherited = any(isinstance(p, str) and sensitive_name(p) for p in tok.path)
        nested = json_secrets(tok.value) if tok.kind == "string" else []
        patterns = [m.group(0) for m in SENSITIVE_VALUE.finditer(tok.value)] if tok.kind == "string" else []
        if direct or inherited or nested or patterns:
            masked.append(tok)
        if direct and tok.kind != "literal":
            known |= _known([tok.value])
        known |= _known(nested) | set(patterns)
    result = Analysis(tuple(masked), frozenset(known), frozenset(scan.line_of(t.start) for t in masked))
    scan.__dict__["_redaction"] = result
    return result


def redacted_text(scan: Scan) -> str:
    """The raw JSON text with every sensitive token replaced by "[redacted]" (line structure is preserved)."""
    out, last = [], 0
    for tok in analyse(scan).masked:
        out.append(scan.text[last : tok.start])
        out.append(f'"{MASK}"')
        last = tok.end
    out.append(scan.text[last:])
    return "".join(out)


def sensitive_values(scan: Scan) -> set[str]:
    """Raw values that must never appear in an output (substring search; short ones are protected by position)."""
    return set(analyse(scan).known)


def sensitive_lines(text: str) -> frozenset[int]:
    """1-based lines of a JSON text that hold a sensitive token; a published diff must not include any of them."""
    return analyse(Scan(text)).lines


def leaks(text: str, known: set[str]) -> list[str]:
    """Descriptions (never the values) of sensitive content found in text."""
    hits = [f"credential-like pattern at offset {m.start()}" for m in SENSITIVE_VALUE.finditer(text)]
    hits += [f"value of a sensitive raw field ({len(v)} chars)" for v in sorted(known) if v in text]
    return hits
