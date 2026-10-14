"""Signatures over export manifests: partners, the customs portal and the compliance archive."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from tallowbrook_reporting import settings

MANIFEST_EC_SIGNATURE = ec.ECDSA(hashes.SHA384())


class ManifestKeyError(ValueError):
    pass


@dataclass(frozen=True)
class ManifestEntry:
    name: str
    size: int
    checksum: str


def manifest_bytes(export_id: str, entries: Iterable[ManifestEntry]) -> bytes:
    body = {
        "export": export_id,
        "files": [asdict(e) for e in sorted(entries, key=lambda e: e.name)],
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def load_export_key(
    path: Path = Path(settings.EXPORT_SIGNER_KEY_PATH),
) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ManifestKeyError("export signer key has the wrong type")
    if not isinstance(key.curve, ec.SECP384R1):
        raise ManifestKeyError(f"export signer key is on {key.curve.name}")
    return key


def sign_partner_manifest(manifest: bytes, ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    return ec_key.sign(manifest, MANIFEST_EC_SIGNATURE)


def load_customs_key(path: Path = Path(settings.CUSTOMS_SIGNER_KEY_PATH)) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ManifestKeyError("customs portal key has the wrong type")
    return key


def sign_customs_manifest(manifest: bytes, rsa_key: rsa.RSAPrivateKey) -> bytes:
    return rsa_key.sign(
        manifest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )


def sign_archive_manifest(manifest: bytes, seed: bytes) -> bytes:
    signer = MLDSA65PrivateKey.from_seed_bytes(seed)
    return signer.sign(manifest, context=b"tallowbrook-export-manifest")
