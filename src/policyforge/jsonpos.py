"""Position-tracking JSON scanner.

Maps every value in a JSON document to the 1-based line where it starts (keyed by RFC 6901 pointer) and
records the span and key path of every scalar token plus the member names of every object, so excerpts can be
redacted in place. Lines are counted on "\n" only (as git and the line numbers in findings do), never on the other
characters str.splitlines() treats as line breaks.
"""

from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass

_WS = re.compile(r"[ \t\n\r]*")
_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][-+]?\d+)?")
_scanstring = json.decoder.scanstring  # type: ignore[attr-defined]


@dataclass(frozen=True)
class Token:
    """A scalar token. kind is string, number or literal; value is the decoded string or the raw text."""

    start: int
    end: int
    path: tuple[str | int, ...]
    value: str
    kind: str = "string"


StringToken = Token


def split_lines(text: str) -> list[str]:
    """Lines split on "\n" only, without the terminators (a trailing newline does not add an empty line)."""
    lines = text.split("\n")
    return lines[:-1] if text.endswith("\n") else lines


def escape(token: str | int) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def pointer(path: tuple[str | int, ...] | list[str | int]) -> str:
    return "".join("/" + escape(p) for p in path)


def split_pointer(ptr: str) -> list[str]:
    if ptr == "":
        return []
    if not ptr.startswith("/"):
        raise ValueError(f"invalid JSON pointer: {ptr!r}")
    return [unescape(p) for p in ptr[1:].split("/")]


def resolve(doc, ptr: str):
    """Value at a JSON pointer; raises KeyError/IndexError when absent."""
    cur = doc
    for part in split_pointer(ptr):
        cur = cur[int(part)] if isinstance(cur, list) else cur[part]
    return cur


class Scan:
    """Scan of one JSON text: `lines[pointer]` is the 1-based line of the value, `strings` the string tokens."""

    def __init__(self, text: str):
        self.text = text
        self._starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.lines: dict[str, int] = {}
        self.tokens: list[Token] = []
        self.members: dict[tuple[str | int, ...], list[str]] = {}
        self.scalars: dict[tuple[str | int, ...], Token] = {}
        try:
            end = self._value(self._skip(0), ())
        except IndexError as exc:
            raise ValueError("unexpected end of JSON text") from exc
        if self._skip(end) != len(text):
            raise ValueError(f"trailing data at line {self.line_of(end)}")

    @property
    def strings(self) -> list[Token]:
        return [t for t in self.tokens if t.kind == "string"]

    @property
    def line_count(self) -> int:
        return len(split_lines(self.text))

    def _add(self, tok: Token) -> int:
        self.tokens.append(tok)
        self.scalars[tok.path] = tok
        return tok.end

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self._starts, pos)

    def nearest_line(self, ptr: str) -> int:
        """Line of the pointer's value, or of its closest existing ancestor."""
        parts = split_pointer(ptr)
        while parts:
            hit = self.lines.get(pointer(parts))
            if hit is not None:
                return hit
            parts.pop()
        return self.lines[""]

    def _skip(self, i: int) -> int:
        return _WS.match(self.text, i).end()

    def _value(self, i: int, path: tuple[str | int, ...]) -> int:
        t = self.text
        self.lines[pointer(path)] = self.line_of(i)
        c = t[i]
        if c == "{":
            keys = self.members.setdefault(path, [])
            i = self._skip(i + 1)
            if t[i] == "}":
                return i + 1
            while True:
                if t[i] != '"':
                    raise ValueError(f"expected an object key at line {self.line_of(i)}")
                key, i = _scanstring(t, i + 1)
                keys.append(key)
                i = self._skip(i)
                if t[i] != ":":
                    raise ValueError(f"expected ':' at line {self.line_of(i)}")
                i = self._skip(self._value(self._skip(i + 1), path + (key,)))
                if t[i] == ",":
                    i = self._skip(i + 1)
                elif t[i] == "}":
                    return i + 1
                else:
                    raise ValueError(f"expected ',' or '}}' at line {self.line_of(i)}")
        if c == "[":
            i = self._skip(i + 1)
            if t[i] == "]":
                return i + 1
            n = 0
            while True:
                i = self._skip(self._value(i, path + (n,)))
                n += 1
                if t[i] == ",":
                    i = self._skip(i + 1)
                elif t[i] == "]":
                    return i + 1
                else:
                    raise ValueError(f"expected ',' or ']' at line {self.line_of(i)}")
        if c == '"':
            value, end = _scanstring(t, i + 1)
            return self._add(Token(i, end, path, value))
        for literal in ("true", "false", "null"):
            if t.startswith(literal, i):
                return self._add(Token(i, i + len(literal), path, literal, "literal"))
        m = _NUMBER.match(t, i)
        if m:
            return self._add(Token(i, m.end(), path, m.group(0), "number"))
        raise ValueError(f"invalid JSON value at line {self.line_of(i)}")
