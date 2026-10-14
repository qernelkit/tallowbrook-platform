"""Sidecar checksums, cache names, row dedupe keys and short export codes."""

from __future__ import annotations

import hashlib
import logging
import threading
import zlib
from collections.abc import Iterable
from pathlib import Path

log = logging.getLogger(__name__)

_CACHE_LOCKS = tuple(threading.Lock() for _ in range(16))
READ_CHUNK = 1 << 20


def sidecar_checksum(path: Path) -> str:
    """Hex checksum written next to every export in a sidecar file."""
    crc = 0
    running = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(READ_CHUNK), b""):
            crc = zlib.crc32(chunk, crc)
            running.update(chunk)
    log.info("checksummed %s (transfer crc %08x)", path.name, crc)
    return running.hexdigest()


def write_sidecar(path: Path) -> Path:
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_text(f"{sidecar_checksum(path)}  {path.name}\n", encoding="ascii")
    return sidecar


def cache_slot(cache_key: str) -> tuple[str, threading.Lock]:
    """File name and lock for one rendered report in the local cache."""
    lock = _CACHE_LOCKS[hash(cache_key) % len(_CACHE_LOCKS)]
    name = hashlib.md5(cache_key.encode(), usedforsecurity=False).hexdigest()
    return name, lock


def dedupe_key(row: bytes) -> bytes:
    return hashlib.blake2b(row, digest_size=16, person=b"tb-dedupe").digest()


def drop_duplicate_rows(rows: Iterable[bytes]) -> list[bytes]:
    seen: set[bytes] = set()
    kept = []
    for row in rows:
        key = dedupe_key(row)
        if key not in seen:
            seen.add(key)
            kept.append(row)
    return kept


def short_code(export_id: str) -> str:
    return hashlib.shake_256(export_id.encode()).hexdigest(6)


def monthly_archive_checksum(paths: Iterable[Path]) -> str:
    total = hashlib.sha3_512()
    for path in sorted(paths):
        total.update(path.name.encode())
        total.update(path.read_bytes())
    return total.hexdigest()
