"""Streaming CSV and JSON Lines rendering for exports."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from decimal import Decimal

from tallowbrook_reporting.models.exports import ExportFormat

DEFAULT_DATE_FORMAT = "%Y-%m-%d"


def format_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, date):
        return value.strftime(DEFAULT_DATE_FORMAT)
    if isinstance(value, Decimal):
        return f"{value:.2f}"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def normalise_rows(
    rows: Iterable[Mapping[str, object]], columns: tuple[str, ...]
) -> list[dict[str, str]]:
    out = []
    for row in rows:
        missing = [c for c in columns if c not in row]
        if missing:
            raise KeyError(f"row is missing columns {missing}")
        out.append({c: format_value(row[c]) for c in columns})
    return out


def render(rows: Iterable[Mapping[str, str]], columns: tuple[str, ...], fmt: ExportFormat) -> bytes:
    if fmt is ExportFormat.JSONL:
        return b"".join(
            json.dumps({c: row.get(c, "") for c in columns}, ensure_ascii=False).encode() + b"\n"
            for row in rows
        )
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row.get(c, "") for c in columns])
    return buf.getvalue().encode("utf-8")


def count_rows(data: bytes, fmt: ExportFormat) -> int:
    lines = data.count(b"\n")
    return lines if fmt is ExportFormat.JSONL else max(lines - 1, 0)
