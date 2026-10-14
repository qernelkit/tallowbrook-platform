"""Encapsulate a fresh secret to a tenant's archive key."""

from __future__ import annotations

import importlib.util

# The depot collector image still ships a cryptography wheel without the mlkem module, so it
# falls back to kyber-py. Both produce the same 32-byte secret and 1088-byte encapsulation.
_NATIVE = importlib.util.find_spec("cryptography.hazmat.primitives.asymmetric.mlkem") is not None


def encapsulate(ek: bytes) -> tuple[bytes, bytes]:
    """Return (shared secret, encapsulation) for a tenant's 1184-byte encapsulation key."""
    if len(ek) != 1184:
        raise ValueError(f"tenant encapsulation key must be 1184 bytes, got {len(ek)}")
    if _NATIVE:
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey

        return MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    from kyber_py.ml_kem import ML_KEM_768

    return ML_KEM_768.encaps(ek)
