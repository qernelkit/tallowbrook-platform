"""Partner-specific file encodings for the nightly partner exports."""

from __future__ import annotations

import csv
import io
import os
from collections.abc import Callable, Iterable, Mapping
from typing import Final

from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish, TripleDES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, Cipher, algorithms, modes

from tallowbrook_reporting.models.exports import PartnerFormat

# What each partner's import tool can open; agreed in the partner onboarding sheets.
PARTNER_CIPHERS: Final[dict[str, Callable[[bytes], BlockCipherAlgorithm]]] = {
    "harbor-customs": TripleDES,
    "lakeshore-audit": Blowfish,
    "prairie-carriers": algorithms.AES256,
}


class PartnerFormatError(ValueError):
    pass


def render_partner_csv(fmt: PartnerFormat, rows: Iterable[Mapping[str, str]]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=list(fmt.columns), delimiter=fmt.delimiter, extrasaction="ignore"
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue().encode(fmt.text_encoding, errors="replace")


def encrypt_partner_file(fmt: PartnerFormat, key: bytes, data: bytes) -> bytes:
    if fmt.partner not in PARTNER_CIPHERS:
        raise PartnerFormatError(f"no file format agreed with {fmt.partner}")
    if len(key) != fmt.key_bytes:
        raise PartnerFormatError(f"{fmt.partner} keys are {fmt.key_bytes} bytes, got {len(key)}")
    algorithm = PARTNER_CIPHERS[fmt.partner](key)
    iv = os.urandom(algorithm.block_size // 8)
    padder = padding.PKCS7(algorithm.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithm, modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()


def partner_file_name(fmt: PartnerFormat, run_date: str) -> str:
    return f"tallowbrook_{fmt.partner.replace('-', '_')}_{run_date}.dat"
