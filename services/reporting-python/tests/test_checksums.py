from __future__ import annotations

from pathlib import Path

from tallowbrook_reporting.exports import checksums


def test_sidecar_is_written_next_to_the_export(tmp_path: Path) -> None:
    export = tmp_path / "shipments.csv"
    export.write_bytes(b"shipment_id\nSH-1\n")
    sidecar = checksums.write_sidecar(export)
    content = sidecar.read_text(encoding="ascii")
    assert content.endswith("  shipments.csv\n")
    assert len(content.split()[0]) == 64


def test_empty_file_has_the_empty_checksum(tmp_path: Path) -> None:
    empty = tmp_path / "empty.csv"
    empty.write_bytes(b"")
    assert checksums.sidecar_checksum(empty) == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_cache_slot_is_stable() -> None:
    name, lock = checksums.cache_slot("acme|shipments|2026-09")
    again, same_lock = checksums.cache_slot("acme|shipments|2026-09")
    assert name == again and len(name) == 32
    assert lock is same_lock


def test_duplicate_rows_are_dropped() -> None:
    rows = [b"a,1", b"b,2", b"a,1"]
    assert checksums.drop_duplicate_rows(rows) == [b"a,1", b"b,2"]


def test_short_code_length() -> None:
    assert len(checksums.short_code("6f1c2a")) == 12
