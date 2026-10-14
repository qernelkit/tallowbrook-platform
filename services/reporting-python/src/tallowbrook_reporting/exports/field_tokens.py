"""Deterministic per-tenant e-mail tokens, so partners can join exports without seeing addresses."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

from tallowbrook_reporting.crypto_helpers import b64url


def tenant_token_key(master_key: bytes, tenant_id: str) -> bytes:
    return KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=64,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=b"field-tokens",
        context=tenant_id.encode(),
        fixed=None,
    ).derive(master_key)


def email_token(tenant_key: bytes, tenant_id: str, email: str) -> str:
    siv = AESSIV(tenant_key)
    token = siv.encrypt(email.strip().casefold().encode(), [tenant_id.encode()])
    return b64url(token)


def tokenize_column(master_key: bytes, tenant_id: str, emails: list[str]) -> list[str]:
    tenant_key = tenant_token_key(master_key, tenant_id)
    return [email_token(tenant_key, tenant_id, e) if e else "" for e in emails]
