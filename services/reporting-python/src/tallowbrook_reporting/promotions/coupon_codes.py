"""Printed coupon codes for shipper promotions: short, unique per campaign, hard to guess."""

from __future__ import annotations

from dataclasses import dataclass

ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
ROUNDS = 6
HALF_BITS = 16
HALF_MASK = (1 << HALF_BITS) - 1
CODE_LENGTH = 7


@dataclass(frozen=True)
class Campaign:
    code: str
    seed: int
    max_serial: int


class CouponFormatError(ValueError):
    pass


def luhn_mod_n(code: str, n: int) -> int:
    """Index of the Luhn mod-N check character for code."""
    factor, total = 2, 0
    for ch in reversed(code):
        addend = factor * ALPHABET.index(ch)
        total += addend // n + addend % n
        factor = 1 if factor == 2 else 2
    return (n - total % n) % n


def _round_keys(campaign: Campaign) -> list[int]:
    keys, state = [], campaign.seed & 0xFFFFFFFFFFFFFFFF
    for _ in range(ROUNDS):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        keys.append(state >> 48)
    return keys


def _mix(half: int, round_key: int) -> int:
    x = (half * 0x9E37 + round_key) & HALF_MASK
    return ((x << 5) | (x >> (HALF_BITS - 5))) & HALF_MASK


def _to_alphabet(block: int) -> str:
    chars = []
    for _ in range(CODE_LENGTH):
        block, rem = divmod(block, len(ALPHABET))
        chars.append(ALPHABET[rem])
    return "".join(reversed(chars))


def encode_coupon(serial: int, campaign: Campaign) -> str:
    if not 0 <= serial <= min(campaign.max_serial, (1 << (2 * HALF_BITS)) - 1):
        raise ValueError(f"serial {serial} is outside campaign {campaign.code}")
    left, right = serial >> HALF_BITS, serial & HALF_MASK
    for round_key in _round_keys(campaign):
        left, right = right, left ^ _mix(right, round_key)
    code = _to_alphabet((left << HALF_BITS) | right)
    code += ALPHABET[luhn_mod_n(code, len(ALPHABET))]
    return f"{campaign.code}-{code}"


def check_coupon(text: str, campaign: Campaign) -> str:
    """Normalise a typed-in coupon and check its format; redemption looks the code up."""
    cleaned = text.strip().upper().replace(" ", "")
    prefix, _, code = cleaned.partition("-")
    if prefix != campaign.code or len(code) != CODE_LENGTH + 1:
        raise CouponFormatError("not a coupon for this campaign")
    if any(ch not in ALPHABET for ch in code):
        raise CouponFormatError("coupon contains characters we never print")
    if ALPHABET[luhn_mod_n(code[:-1], len(ALPHABET))] != code[-1]:
        raise CouponFormatError("coupon check character does not match")
    return f"{prefix}-{code}"
