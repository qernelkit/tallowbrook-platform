"""Wrap a compliance-archive data key for one tenant."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, keywrap
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tallowbrook_reporting.exports import kem_compat


@dataclass(frozen=True)
class WrappedArchiveKey:
    tenant_id: str
    encapsulation: bytes
    wrapped_key: bytes

    def to_record(self) -> dict[str, str]:
        return {
            "tenant_id": self.tenant_id,
            "encapsulation": self.encapsulation.hex(),
            "wrapped_key": self.wrapped_key.hex(),
        }


def wrap_archive_key(tenant_id: str, encapsulation_key: bytes, dek: bytes) -> WrappedArchiveKey:
    shared, encapsulation = kem_compat.encapsulate(encapsulation_key)
    kek = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=None,
        info=b"tallowbrook archive kek v2",
    ).derive(shared)
    wrapped = keywrap.aes_key_wrap(kek, dek)
    return WrappedArchiveKey(tenant_id, encapsulation, wrapped)
