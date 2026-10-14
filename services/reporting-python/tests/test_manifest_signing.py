from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tallowbrook_reporting.exports import manifest_signing


def test_export_key_loads_from_pem(tmp_path: Path, export_key: ec.EllipticCurvePrivateKey) -> None:
    path = tmp_path / "export.key"
    path.write_bytes(
        export_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    loaded = manifest_signing.load_export_key(path)
    assert loaded.public_key().public_numbers() == export_key.public_key().public_numbers()


def test_manifest_is_canonical() -> None:
    entries = [
        manifest_signing.ManifestEntry("b.csv", 2, "bb"),
        manifest_signing.ManifestEntry("a.csv", 1, "aa"),
    ]
    first = manifest_signing.manifest_bytes("x", entries)
    assert first == manifest_signing.manifest_bytes("x", list(reversed(entries)))
    assert first.startswith(b'{"export":"x","files":[{"checksum":"aa"')
