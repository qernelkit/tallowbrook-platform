"""Depots, their stock levels and the readings collected from depot gateways."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal


@dataclass(frozen=True)
class Depot:
    key: str
    name: str
    endpoint: str
    security: str | None = None
    gateway: str | None = None
    server_cert: str | None = None
    poll_seconds: int = 30


@dataclass
class DepotStock:
    depot: str
    as_of: date
    diesel_litres: Decimal
    adblue_litres: Decimal
    road_salt_tonnes: Decimal
    pallets_free: int

    def needs_salt_order(self, forecast_tonnes: Decimal, reserve_tonnes: Decimal) -> bool:
        return self.road_salt_tonnes - forecast_tonnes < reserve_tonnes


@dataclass(frozen=True)
class DepotReading:
    depot: str
    node: str
    value: float
    unit: str
    read_at: datetime

    def as_row(self) -> dict[str, str]:
        return {
            "depot": self.depot,
            "node": self.node,
            "value": f"{self.value:.3f}",
            "unit": self.unit,
            "read_at": self.read_at.isoformat(),
        }
