"""Small encoding helpers shared by the API handlers and the support tools."""

from __future__ import annotations

import base64
import binascii
import re

PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----", re.S)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def to_hex(raw: bytes) -> str:
    return binascii.hexlify(raw).decode("ascii")


def encode_idempotency_key(parts: list[str]) -> str:
    return base64.urlsafe_b64encode("|".join(parts).encode()).decode()


def encrypt_for_display(value: str) -> str:
    """Mask all but the last four characters, for logs and support screens."""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def split_pem_blocks(text: str) -> list[tuple[str, str]]:
    """Split text pasted into a support ticket into (label, body) pairs."""
    return [(m.group(1), m.group(2).strip()) for m in PEM_BLOCK.finditer(text)]
