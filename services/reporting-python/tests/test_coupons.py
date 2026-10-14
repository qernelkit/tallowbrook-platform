from __future__ import annotations

import secrets

import pytest

from tallowbrook_reporting.promotions.coupon_codes import (
    Campaign,
    CouponFormatError,
    check_coupon,
    encode_coupon,
)

SPRING = Campaign(code="SPR26", seed=secrets.randbits(64), max_serial=50_000)


def test_codes_are_unique() -> None:
    codes = {encode_coupon(n, SPRING) for n in range(2_000)}
    assert len(codes) == 2_000


def test_printed_code_passes_the_check() -> None:
    code = encode_coupon(1234, SPRING)
    assert check_coupon(code.lower(), SPRING) == code


def test_typo_is_caught() -> None:
    code = encode_coupon(77, SPRING)
    mistyped = code[:-2] + ("A" if code[-2] != "A" else "B") + code[-1]
    with pytest.raises(CouponFormatError):
        check_coupon(mistyped, SPRING)


def test_serial_outside_campaign() -> None:
    with pytest.raises(ValueError):
        encode_coupon(50_001, SPRING)
