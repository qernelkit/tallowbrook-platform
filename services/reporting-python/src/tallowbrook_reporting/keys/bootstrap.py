"""First-run key setup for a tenant: delivery-receipt signing and the archive key pair."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

from tallowbrook_reporting import settings

log = logging.getLogger(__name__)

RECEIPT_FILE = "receipt-signing.pem"
ARCHIVE_FILE = "archive.pem"


@dataclass(frozen=True)
class TenantKeys:
    tenant_id: str
    receipt_verify_key: bytes
    archive_encapsulation_key: bytes


class TenantKeysExist(FileExistsError):
    pass


def _write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _to_pem(key: ed25519.Ed25519PrivateKey | MLKEM768PrivateKey) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def init_tenant_keys(tenant_id: str, root: Path = settings.TENANT_SECRETS_DIR) -> TenantKeys:
    tenant_dir = root / tenant_id
    if (tenant_dir / RECEIPT_FILE).exists() or (tenant_dir / ARCHIVE_FILE).exists():
        raise TenantKeysExist(f"keys for tenant {tenant_id} already exist in {tenant_dir}")
    tenant_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    receipt_key = ed25519.Ed25519PrivateKey.generate()
    archive_key = MLKEM768PrivateKey.generate()

    _write_secret(tenant_dir / RECEIPT_FILE, _to_pem(receipt_key))
    _write_secret(tenant_dir / ARCHIVE_FILE, _to_pem(archive_key))
    keys = TenantKeys(
        tenant_id=tenant_id,
        receipt_verify_key=receipt_key.public_key().public_bytes_raw(),
        archive_encapsulation_key=archive_key.public_key().public_bytes_raw(),
    )
    log.info("created keys for tenant %s", tenant_id)
    return keys
