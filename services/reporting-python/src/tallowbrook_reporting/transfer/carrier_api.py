"""Client for the carrier booking API (pickups, proof of delivery, rate cards)."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from tallowbrook_reporting import settings
from tallowbrook_reporting.transfer.tls import carrier_context

log = logging.getLogger(__name__)

USER_AGENT = "tallowbrook-reporting/3.14"


class CarrierApiError(RuntimeError):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"carrier API returned {status}: {detail}")
        self.status = status


@dataclass(frozen=True)
class ProofOfDelivery:
    delivery_id: str
    consignee: str
    delivered_at: str
    photo_ref: str | None


def _request(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"{settings.CARRIER_API_BASE}{path}",
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.carrier_api_token()}",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, context=carrier_context(), timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        raise CarrierApiError(exc.code, detail) from exc


def proof_of_delivery(delivery_id: str) -> ProofOfDelivery:
    doc = _request("GET", f"/deliveries/{delivery_id}/pod")
    return ProofOfDelivery(
        delivery_id=delivery_id,
        consignee=doc["consignee"],
        delivered_at=doc["delivered_at"],
        photo_ref=doc.get("photo_ref"),
    )


def rate_card(carrier: str, lane: str) -> list[dict[str, Any]]:
    doc = _request("GET", f"/carriers/{carrier}/rates?lane={lane}")
    rates = doc.get("rates", [])
    log.debug("carrier %s lane %s: %d rates", carrier, lane, len(rates))
    return rates


def book_pickup(carrier: str, shipment_id: str, ready_at: str) -> str:
    doc = _request(
        "POST", "/pickups", {"carrier": carrier, "shipment": shipment_id, "ready_at": ready_at}
    )
    return doc["pickup_id"]
