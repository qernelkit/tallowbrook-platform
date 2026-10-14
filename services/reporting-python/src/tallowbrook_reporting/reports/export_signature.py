"""Detached signatures (.p7s) written next to each signed export."""

from __future__ import annotations

from functools import cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from tallowbrook_reporting import settings
from tallowbrook_reporting.exports import manifest_signing


@cache
def _export_cert() -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(settings.EXPORT_SIGNER_CERT_PATH).read_bytes())


def detached_signature(export_path: Path) -> Path:
    export_cert = _export_cert()
    export_key = manifest_signing.load_export_key()
    sig = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(export_path.read_bytes())
        .add_signer(export_cert, export_key, hashes.SHA384())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
        )
    )
    out = export_path.with_name(export_path.name + ".p7s")
    out.write_bytes(sig)
    return out
