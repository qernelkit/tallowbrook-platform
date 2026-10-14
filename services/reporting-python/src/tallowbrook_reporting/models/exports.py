"""Export jobs and the per-partner file formats."""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


class ExportFormat(enum.StrEnum):
    CSV = "csv"
    JSONL = "jsonl"


class ExportStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Audience(enum.StrEnum):
    CUSTOMER = "customer"
    PARTNER = "partner"
    CUSTOMS = "customs"
    ARCHIVE = "archive"
    SAMPLE = "sample"


@dataclass(frozen=True)
class PartnerFormat:
    partner: str
    key_bytes: int
    delimiter: str = ","
    text_encoding: str = "utf-8"
    columns: tuple[str, ...] = ()


PARTNER_FORMATS: dict[str, PartnerFormat] = {
    "harbor-customs": PartnerFormat(
        "harbor-customs",
        key_bytes=24,
        delimiter=";",
        text_encoding="latin-1",
        columns=("shipment_id", "hs_code", "declared_value", "origin", "destination"),
    ),
    "lakeshore-audit": PartnerFormat(
        "lakeshore-audit",
        key_bytes=16,
        delimiter="|",
        columns=("invoice_id", "customer_id", "amount", "currency", "issued_on"),
    ),
    "prairie-carriers": PartnerFormat(
        "prairie-carriers",
        key_bytes=32,
        columns=("shipment_id", "carrier_ref", "pickup_at", "delivered_at", "weight_kg"),
    ),
}


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class ExportJob:
    tenant_id: str
    report: str
    audience: Audience
    fmt: ExportFormat = ExportFormat.CSV
    partner: str | None = None
    columns: tuple[str, ...] = ()
    requested_by: str = ""
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    created_at: datetime = field(default_factory=_now)
    status: ExportStatus = ExportStatus.QUEUED
    error: str | None = None

    @property
    def ref(self) -> bytes:
        return self.id.bytes

    @property
    def object_key(self) -> str:
        return f"{self.tenant_id}/{self.created_at:%Y/%m}/{self.id}.{self.fmt.value}"

    def partner_format(self) -> PartnerFormat:
        if self.partner is None or self.partner not in PARTNER_FORMATS:
            raise LookupError(f"no partner format for {self.partner!r}")
        return PARTNER_FORMATS[self.partner]


@dataclass(frozen=True)
class ExportResult:
    job_id: uuid.UUID
    object_key: str
    size: int
    checksum: str
    rows: int
