from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tallowbrook_reporting.telemetry import readings
from tallowbrook_reporting.telemetry.opcua_collector import load_depots


def test_depots_load_sorted(depots_file: Path) -> None:
    depots = load_depots(depots_file)
    assert [d.key for d in depots] == ["joliet", "peoria"]
    assert depots[1].name == "Peoria" and depots[1].poll_seconds == 60


def test_imperial_gateways_convert_to_litres() -> None:
    assert readings.convert("diesel_tank", 10, imperial=True) == pytest.approx(37.854, rel=1e-3)
    assert readings.convert("cold_room", 41.0, imperial=True) == pytest.approx(5.0)


def test_readings_need_one_value_per_node() -> None:
    with pytest.raises(ValueError):
        readings.to_readings("joliet", ["diesel_tank"], [], datetime.now(UTC), imperial=False)


def test_attestation_document() -> None:
    doc = {
        "gateways": ["gw-1", "gw-2"],
        "batch": secrets.token_hex(32),
        "signature": secrets.token_hex(96),
    }
    raw = json.dumps(doc)
    att = readings.parse_attestation(raw)
    assert att.gateway_ids == ("gw-1", "gw-2")
    assert len(att.aggregate_signature) == 96
