"""Monthly customer statements: merge the rendered pages into one PDF per customer."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import pikepdf

from tallowbrook_reporting.models.customers import Customer

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class StatementPeriod:
    year: int
    month: int

    @property
    def label(self) -> str:
        return date(self.year, self.month, 1).strftime("%B %Y")

    @property
    def slug(self) -> str:
        return f"{self.year:04d}-{self.month:02d}"


def statement_path(out_dir: Path, customer: Customer, period: StatementPeriod) -> Path:
    return out_dir / customer.tenant_id / f"statement-{customer.id}-{period.slug}.pdf"


def merge_pages(parts: Sequence[Path], dst: Path, *, title: str) -> int:
    """Concatenate the rendered parts (cover, invoices, shipment detail) into dst."""
    if not parts:
        raise ValueError("no statement parts to merge")
    dst.parent.mkdir(parents=True, exist_ok=True)
    with pikepdf.new() as merged:
        for part in parts:
            with pikepdf.open(part) as src:
                merged.pages.extend(src.pages)
        with merged.open_metadata() as meta:
            meta["dc:title"] = title
            meta["dc:creator"] = ["Tallowbrook Logistics"]
        merged.save(dst, linearize=True)
        pages = len(merged.pages)
    log.info("merged %d parts into %s (%d pages)", len(parts), dst.name, pages)
    return pages


def build_statement(
    customer: Customer, period: StatementPeriod, parts: Sequence[Path], out_dir: Path
) -> Path:
    dst = statement_path(out_dir, customer, period)
    merge_pages(parts, dst, title=f"{customer.name} statement, {period.label}")
    return dst
