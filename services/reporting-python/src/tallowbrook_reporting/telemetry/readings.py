"""Depot gateway node ids, unit conversion and reading records."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from tallowbrook_reporting.models.depots import DepotReading

NODE_IDS: dict[str, str] = {
    "diesel_tank": "ns=2;s=Depot.Fuel.DieselTank.Level",
    "adblue_tank": "ns=2;s=Depot.Fuel.AdBlueTank.Level",
    "cold_room": "ns=2;s=Depot.ColdRoom.TempC",
    "dock_doors_open": "ns=2;s=Depot.Docks.OpenCount",
    "yard_salt": "ns=2;s=Depot.Yard.SaltStock",
}
ATTESTATION_NODE = "ns=2;s=Depot.Attestation.LastBatch"

UNITS: dict[str, str] = {
    "diesel_tank": "l",
    "adblue_tank": "l",
    "cold_room": "degC",
    "dock_doors_open": "count",
    "yard_salt": "t",
}

US_GALLON_LITRES = 3.785411784


@dataclass(frozen=True)
class BatchAttestation:
    gateway_ids: tuple[str, ...]
    batch_hash: bytes
    aggregate_signature: bytes


def convert(node: str, raw: object, *, imperial: bool = False) -> float:
    if not isinstance(raw, int | float):
        raise TypeError(f"{node}: expected a number, got {type(raw).__name__}")
    value = float(raw)
    if imperial and UNITS.get(node) == "l":
        return value * US_GALLON_LITRES
    if imperial and node == "cold_room":
        return (value - 32.0) * 5.0 / 9.0
    return value


def to_readings(
    depot: str, names: Sequence[str], values: Sequence[object], read_at: datetime, *, imperial: bool
) -> list[DepotReading]:
    if len(names) != len(values):
        raise ValueError(f"{depot}: {len(names)} nodes but {len(values)} values")
    return [
        DepotReading(depot, name, convert(name, raw, imperial=imperial), UNITS[name], read_at)
        for name, raw in zip(names, values, strict=True)
    ]


def parse_attestation(raw: object) -> BatchAttestation:
    if not isinstance(raw, str):
        raise TypeError("attestation node must hold a JSON string")
    doc = json.loads(raw)
    return BatchAttestation(
        gateway_ids=tuple(doc["gateways"]),
        batch_hash=bytes.fromhex(doc["batch"]),
        aggregate_signature=bytes.fromhex(doc["signature"]),
    )
