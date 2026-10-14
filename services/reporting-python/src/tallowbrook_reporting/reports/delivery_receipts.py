"""Proof-of-delivery pages for the monthly statement appendix."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DeliveryReceipt:
    delivery_id: str
    consignee: str
    delivered_at: datetime
    driver_id: str
    signature_png: bytes | None = None
    photo_ref: str | None = None


class ReceiptIncomplete(ValueError):
    pass


def receipt_lines(receipt: DeliveryReceipt) -> list[str]:
    if not receipt.signature_png:
        raise ReceiptIncomplete(f"delivery {receipt.delivery_id} has no consignee signature image")
    lines = [
        f"Delivery {receipt.delivery_id}",
        f"Received by {receipt.consignee}",
        f"At {receipt.delivered_at:%Y-%m-%d %H:%M} by driver {receipt.driver_id}",
    ]
    if receipt.photo_ref:
        lines.append(f"Photo {receipt.photo_ref}")
    return lines


def appendix(receipts: Iterable[DeliveryReceipt]) -> tuple[list[list[str]], list[str]]:
    """Pages for the complete receipts, and the delivery ids still missing a signature image."""
    pages, missing = [], []
    for receipt in sorted(receipts, key=lambda r: r.delivered_at):
        try:
            pages.append(receipt_lines(receipt))
        except ReceiptIncomplete:
            missing.append(receipt.delivery_id)
    return pages, missing
