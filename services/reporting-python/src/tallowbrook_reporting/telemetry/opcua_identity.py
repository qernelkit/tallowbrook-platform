"""The OPC UA application identity this service presents to depot gateways."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from tallowbrook_reporting import settings

log = logging.getLogger(__name__)

APPLICATION_URI = "urn:tallowbrook:reporting:telemetry-client"
VALIDITY = timedelta(days=825)


def ensure_application_identity(
    state_dir: Path = settings.TELEMETRY_STATE_DIR,
) -> tuple[Path, Path]:
    """Create the client identity on first start; reuse it afterwards."""
    cert_path = state_dir / "client-cert.der"
    key_path = state_dir / "client-key.pem"
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    state_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name.from_rfc4514_string("CN=Tallowbrook Reporting,O=Tallowbrook Logistics,C=US")
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + VALIDITY)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(APPLICATION_URI)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(Encoding.DER))
    log.info("created OPC UA application identity in %s", state_dir)
    return cert_path, key_path
