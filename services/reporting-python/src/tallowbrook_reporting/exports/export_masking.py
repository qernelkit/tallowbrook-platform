"""Column masking for the sample extracts handed to analysts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from tallowbrook_reporting.crypto_helpers import b64url, b64url_decode

MASKED_COLUMNS = frozenset({"consignee_name", "consignee_phone", "delivery_address"})


def mask_column(value: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("mask key is empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(value))


def mask_rows(rows: Iterable[Mapping[str, str]], key: bytes) -> list[dict[str, str]]:
    out = []
    for row in rows:
        masked = dict(row)
        for column in MASKED_COLUMNS & row.keys():
            masked[column] = b64url(mask_column(row[column].encode("utf-8"), key))
        out.append(masked)
    return out


def unmask_value(text: str, key: bytes) -> str:
    # the mask is its own inverse
    return mask_column(b64url_decode(text), key).decode("utf-8")
