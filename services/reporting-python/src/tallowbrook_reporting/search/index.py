"""In-memory index over report titles and descriptions for the portal search box."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from tallowbrook_reporting.search.tokens import Token, tokenize


@dataclass(frozen=True)
class ReportDoc:
    id: str
    title: str
    description: str
    fields: dict[str, str]


class ReportIndex:
    def __init__(self) -> None:
        self._docs: dict[str, ReportDoc] = {}
        self._postings: dict[str, set[str]] = defaultdict(set)

    def add(self, doc: ReportDoc) -> None:
        self._docs[doc.id] = doc
        for word in f"{doc.title} {doc.description}".lower().split():
            self._postings[word.strip(".,;:()")].add(doc.id)

    def __len__(self) -> int:
        return len(self._docs)

    def _matches_field(self, doc: ReportDoc, field: str, value: str) -> bool:
        return doc.fields.get(field, "").lower() == value.lower()

    def _words(self, text: str) -> set[str]:
        hits: set[str] | None = None
        for word in text.lower().split():
            ids = self._postings.get(word, set())
            hits = set(ids) if hits is None else hits & ids
        return hits or set()

    def search(self, query: str) -> list[ReportDoc]:
        tokens: list[Token] = tokenize(query)
        result: set[str] = set(self._docs)
        negate = False
        pending_field: str | None = None
        for tok in tokens:
            if tok.kind == "op":
                negate = tok.text == "NOT"
                continue
            if tok.kind == "field":
                pending_field = tok.text
                continue
            if pending_field:
                ids = {
                    d.id
                    for d in self._docs.values()
                    if self._matches_field(d, pending_field, tok.text)
                }
                pending_field = None
            else:
                ids = self._words(tok.text)
            result = result - ids if negate else result & ids
            negate = False
        return sorted((self._docs[i] for i in result), key=lambda d: d.title)
