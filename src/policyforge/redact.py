"""Second-layer redaction. The adapters already drop sensitive raw fields; this catches whatever slips through
(sensitive-looking key names, credential-looking values) and records what was removed by path, never by value.
The same rules redact raw-file excerpts and detect leaks in any output text."""

from __future__ import annotations

import re
from typing import Any

from policyforge.jsonpos import Scan, StringToken, escape

SENSITIVE_NAME = re.compile(
    r"passw(or)?d|secret|token|credential|connection_?string|private_?key|account_?key|user_?data|sas_?token", re.I
)
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


def redact_tree(obj: Any, path: str = "") -> tuple[Any, list[dict[str, str]]]:
    """Drop keys with sensitive names and mask credential-looking strings. Returns (clean copy, records)."""
    records: list[dict[str, str]] = []

    def walk(node: Any, at: str) -> Any:
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                sub = f"{at}/{escape(key)}"
                if SENSITIVE_NAME.search(key):
                    records.append({"path": sub, "reason": "sensitive-name", "action": "dropped"})
                    continue
                out[key] = walk(value, sub)
            return out
        if isinstance(node, list):
            return [walk(v, f"{at}/{i}") for i, v in enumerate(node)]
        if isinstance(node, str) and SENSITIVE_VALUE.search(node):
            records.append({"path": at, "reason": "sensitive-value", "action": "masked"})
            return MASK
        return node

    return walk(obj, path), records


def sensitive_token(tok: StringToken) -> bool:
    return any(isinstance(p, str) and SENSITIVE_NAME.search(p) for p in tok.path) or bool(
        SENSITIVE_VALUE.search(tok.value)
    )


def redacted_text(scan: Scan) -> str:
    """The raw JSON text with every sensitive string token replaced by "[redacted]" (lines are preserved)."""
    out, last = [], 0
    for tok in scan.strings:
        if sensitive_token(tok):
            out.append(scan.text[last : tok.start])
            out.append(f'"{MASK}"')
            last = tok.end
    out.append(scan.text[last:])
    return "".join(out)


def sensitive_values(scan: Scan) -> set[str]:
    """Raw values that must never appear in an output: sensitive tokens and credential-looking substrings."""
    found: set[str] = set()
    for tok in scan.strings:
        if sensitive_token(tok) and len(tok.value) >= 8:
            found.add(tok.value)
        found.update(m.group(0) for m in SENSITIVE_VALUE.finditer(tok.value))
    return found


def leaks(text: str, known: set[str]) -> list[str]:
    """Descriptions (never the values) of sensitive content found in text."""
    hits = [f"credential-like pattern at offset {m.start()}" for m in SENSITIVE_VALUE.finditer(text)]
    hits += [f"value of a sensitive raw field ({len(v)} chars)" for v in sorted(known) if v in text]
    return hits
