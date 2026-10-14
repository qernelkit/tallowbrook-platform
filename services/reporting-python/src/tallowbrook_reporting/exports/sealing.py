"""Chunked sealing of export files with a per-export data key."""

from __future__ import annotations

import binascii
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

NONCE_BYTES = 12
CHUNK_BYTES = 1 << 20


class ExportKeyError(ValueError):
    """A data key of the wrong length reached the sealing code."""


def new_data_key(export_ref: bytes) -> bytes:
    dek = AESGCM.generate_key(bit_length=256)
    log.debug("issued data key for export %s", binascii.hexlify(export_ref).decode())
    return dek


def _aead(key: bytes) -> AESGCM:
    if len(key) != 32:
        raise ExportKeyError(f"data key must be 32 bytes, got {len(key)}")
    return AESGCM(key)


def seal_chunk(key: bytes, chunk: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + _aead(key).encrypt(nonce, chunk, aad)


def open_chunk(key: bytes, sealed: bytes, aad: bytes) -> bytes:
    nonce, body = sealed[:NONCE_BYTES], sealed[NONCE_BYTES:]
    return _aead(key).decrypt(nonce, body, aad)


def chunk_aad(export_ref: bytes, index: int) -> bytes:
    return export_ref + index.to_bytes(4, "big")


def seal_stream(key: bytes, export_ref: bytes, data: bytes) -> list[bytes]:
    return [
        seal_chunk(key, data[offset : offset + CHUNK_BYTES], chunk_aad(export_ref, n))
        for n, offset in enumerate(range(0, len(data), CHUNK_BYTES))
    ]
