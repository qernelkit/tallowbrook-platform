"""Wrap export data keys with the wrapping key that never leaves the hardware module."""

from __future__ import annotations

import pkcs11
from pkcs11 import KeyType, Mechanism, ObjectClass
from pkcs11.types import EncryptMixin

from tallowbrook_reporting import settings


class KeyWrapUnavailable(RuntimeError):
    pass


def wrap_with_hsm_kek(dek: bytes) -> bytes:
    lib = pkcs11.lib(settings.HSM_MODULE_PATH)
    token = lib.get_token(token_label=settings.HSM_TOKEN_LABEL)
    with token.open(user_pin=settings.hsm_pin()) as session:
        kek = session.get_key(ObjectClass.SECRET_KEY, KeyType.AES, label=settings.HSM_KEK_LABEL)
        if not isinstance(kek, EncryptMixin):
            raise KeyWrapUnavailable("the export wrapping key cannot wrap keys")
        wrapped = kek.encrypt(dek, mechanism=Mechanism.AES_KEY_WRAP)
    return wrapped if isinstance(wrapped, bytes) else b"".join(wrapped)
