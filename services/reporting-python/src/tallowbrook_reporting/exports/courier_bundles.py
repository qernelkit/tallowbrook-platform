"""Open the upload bundles couriers send from their handhelds (proof-of-delivery batches)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from tallowbrook_reporting import settings
from tallowbrook_reporting.exports import sealing

MAGIC = b"TBCB"
HEADER = struct.Struct(">4sH32s")
SUPPORTED_VERSIONS = frozenset({1})


class BundleError(ValueError):
    pass


@dataclass(frozen=True)
class BundleHeader:
    version: int
    ephemeral_public: bytes
    raw: bytes


def parse_header(blob: bytes) -> tuple[BundleHeader, bytes]:
    if len(blob) < HEADER.size:
        raise BundleError("bundle is shorter than its header")
    magic, version, ephemeral = HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise BundleError("not a courier bundle")
    if version not in SUPPORTED_VERSIONS:
        raise BundleError(f"unsupported bundle version {version}")
    return BundleHeader(version, ephemeral, blob[: HEADER.size]), blob[HEADER.size :]


@cache
def _courier_key() -> x25519.X25519PrivateKey:
    pem = Path(settings.COURIER_BUNDLE_KEY_PATH).read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise BundleError("courier bundle key has the wrong type")
    return key


def open_bundle(blob: bytes) -> bytes:
    header, payload = parse_header(blob)
    peer = x25519.X25519PublicKey.from_public_bytes(header.ephemeral_public)
    shared = _courier_key().exchange(peer)
    key = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=b"tallowbrook-courier-bundle",
    ).derive(shared)
    return sealing.open_chunk(key, payload, header.raw)


def split_records(body: bytes) -> list[dict[str, str]]:
    records = []
    for line in body.decode("utf-8").splitlines():
        if not line.strip():
            continue
        delivery_id, signed_at, consignee, photo_ref = line.split("\t")
        records.append(
            {
                "delivery_id": delivery_id,
                "signed_at": signed_at,
                "consignee": consignee,
                "photo_ref": photo_ref,
            }
        )
    return records
