"""Exports a customer opens with a phrase they chose in the portal."""

from __future__ import annotations

from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tallowbrook_reporting.exports import sealing

EXPORT_KDF_SALT: Final = bytes.fromhex("96102ee8cca17744d10c63061ca3542a")
MIN_PHRASE_LENGTH: Final = 12


class PhraseTooShort(ValueError):
    pass


def _derive(phrase: str) -> bytes:
    if len(phrase) < MIN_PHRASE_LENGTH:
        raise PhraseTooShort(f"phrase must be at least {MIN_PHRASE_LENGTH} characters")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=EXPORT_KDF_SALT,
        iterations=600_000,
    )
    return kdf.derive(phrase.encode("utf-8"))


def protect_export(data: bytes, phrase: str, export_ref: bytes) -> bytes:
    return sealing.seal_chunk(_derive(phrase), data, export_ref)


def open_export(sealed: bytes, phrase: str, export_ref: bytes) -> bytes:
    return sealing.open_chunk(_derive(phrase), sealed, export_ref)
