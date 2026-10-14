"""Lexer for the report search box: words, quoted phrases, field filters and AND/OR/NOT."""

from __future__ import annotations

import re
from typing import NamedTuple

_LEXER = re.compile(
    r'\s*(?:(?P<phrase>"[^"]*")|(?P<op>\b(?:AND|OR|NOT)\b)|(?P<field>[a-z_]+):|(?P<word>[^\s"]+))'
)


class Token(NamedTuple):
    kind: str
    text: str
    pos: int


def tokenize(query: str) -> list[Token]:
    out: list[Token] = []
    pos = 0
    while pos < len(query):
        m = _LEXER.match(query, pos)
        if m is None or m.end() == pos:
            break
        kind = m.lastgroup or "word"
        text = m.group(kind)
        if kind == "phrase":
            text = text[1:-1]
        out.append(Token(kind, text, m.start(kind)))
        pos = m.end()
    return out


def has_field_filters(tokens: list[Token]) -> bool:
    return any(t.kind == "field" for t in tokens)
