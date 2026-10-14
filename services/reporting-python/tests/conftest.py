from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

SAMPLE_ROWS = [
    {"shipment_id": "SH-1001", "origin": "Joliet", "destination": "Peoria", "weight_kg": "812.5"},
    {"shipment_id": "SH-1002", "origin": "Galesburg", "destination": "Joliet", "weight_kg": "95.0"},
    {
        "shipment_id": "SH-1003",
        "origin": "Peoria",
        "destination": "Galesburg",
        "weight_kg": "1440.0",
    },
]


@pytest.fixture
def sample_rows() -> list[dict[str, str]]:
    return [dict(r) for r in SAMPLE_ROWS]


@pytest.fixture
def export_key() -> ec.EllipticCurvePrivateKey:
    key = ec.generate_private_key(ec.SECP384R1())
    return key


@pytest.fixture
def spool_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    from tallowbrook_reporting import settings

    spool = tmp_path / "spool"
    monkeypatch.setattr(settings, "EXPORT_SPOOL_DIR", spool)
    yield spool


@pytest.fixture
def depots_file(tmp_path: Path) -> Path:
    path = tmp_path / "depots.toml"
    path.write_text(
        '[depots.joliet]\nname = "Joliet"\nendpoint = "opc.tcp://gw.test:4840/"\ngateway = "g4"\n'
        '[depots.peoria]\nendpoint = "opc.tcp://gw2.test:4840/"\ngateway = "g1"\npoll_seconds = 60\n',
        encoding="utf-8",
    )
    return path
