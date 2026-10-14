"""One-time codes for staff and carrier-portal sign-in."""

from __future__ import annotations

import hashlib

import pyotp

ISSUER = "Tallowbrook Reports"


def carrier_portal_totp(seed: str) -> pyotp.TOTP:
    return pyotp.TOTP(seed, digest=hashlib.sha256, digits=8, interval=30)


def staff_totp(seed: str) -> pyotp.TOTP:
    # authenticator apps on staff phones
    return pyotp.TOTP(seed)


def enrolment_uri(seed: str, email: str) -> str:
    return staff_totp(seed).provisioning_uri(name=email, issuer_name=ISSUER)


def check_code(otp: pyotp.TOTP, code: str) -> bool:
    return code.isdigit() and otp.verify(code, valid_window=1)
