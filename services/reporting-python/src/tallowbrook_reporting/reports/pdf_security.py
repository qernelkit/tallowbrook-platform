"""Password protection for statement PDFs."""

from __future__ import annotations

from pathlib import Path

import pikepdf


def protect_for_customs_portal(src: Path, dst: Path, owner: str, user: str) -> None:
    # the customs portal viewer only opens R4 files
    with pikepdf.open(src) as pdf:
        pdf.save(
            dst,
            encryption=pikepdf.Encryption(owner=owner, user=user, R=4, aes=False, metadata=False),
        )


def protect_statement(src: Path, dst: Path, owner: str, user: str) -> None:
    with pikepdf.open(src) as pdf:
        pdf.save(dst, encryption=pikepdf.Encryption(owner=owner, user=user))


def is_protected(path: Path) -> bool:
    try:
        with pikepdf.open(path):
            return False
    except pikepdf.PasswordError:
        return True
