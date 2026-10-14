"""Local disk cache of rendered reports, stored in 4 KiB blocks."""

from __future__ import annotations

import logging
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

log = logging.getLogger(__name__)

_LENGTH = struct.Struct(">Q")


def _tweak(block_no: int) -> bytes:
    return block_no.to_bytes(16, "little")


class BlobCache:
    BLOCK = 4096

    def __init__(self, root: Path, key: bytes) -> None:
        if len(key) != 64:
            raise ValueError(f"cache key must be 64 bytes, got {len(key)}")
        self._root = root
        self._key = key
        root.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        if "/" in name or name.startswith("."):
            raise ValueError(f"bad cache entry name {name!r}")
        return self._root / name

    def _apply(self, data: bytes, *, store: bool) -> bytes:
        out = bytearray()
        for block_no, offset in enumerate(range(0, len(data), self.BLOCK)):
            cipher = Cipher(algorithms.AES(self._key), modes.XTS(_tweak(block_no)))
            ctx = cipher.encryptor() if store else cipher.decryptor()
            out += ctx.update(data[offset : offset + self.BLOCK]) + ctx.finalize()
        return bytes(out)

    def put(self, name: str, data: bytes) -> None:
        # each block needs at least 16 bytes, so pad to the next multiple of 16
        pad = -len(data) % 16 if data else 16
        sealed = self._apply(data + bytes(pad), store=True)
        self._path(name).write_bytes(_LENGTH.pack(len(data)) + sealed)
        log.debug("cached %s (%d bytes)", name, len(data))

    def get(self, name: str) -> bytes | None:
        path = self._path(name)
        if not path.exists():
            return None
        raw = path.read_bytes()
        (length,) = _LENGTH.unpack_from(raw)
        return self._apply(raw[_LENGTH.size :], store=False)[:length]

    def evict(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)

    def size_bytes(self) -> int:
        return sum(p.stat().st_size for p in self._root.iterdir() if p.is_file())
