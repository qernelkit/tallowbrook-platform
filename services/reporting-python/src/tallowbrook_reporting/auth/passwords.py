"""Portal passwords and API client secrets."""

from __future__ import annotations

import logging

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from passlib.handlers.pbkdf2 import pbkdf2_sha256

log = logging.getLogger(__name__)

# The carrier portal imports user hashes in this format only.
PORTAL_PBKDF2_ROUNDS = 310_000
PBKDF2_PREFIX = "$pbkdf2-sha256$"


class PortalPasswords:
    def __init__(self) -> None:
        self._hasher = PasswordHasher()

    def _upgrade(self, user_id: str, password: str) -> str:
        log.info("rehashing %s with argon2id", user_id)
        return self._hasher.hash(password)

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, user_id: str, password: str, stored: str) -> tuple[bool, str | None]:
        """Check a login; the second value is a replacement hash to store, if any."""
        if stored.startswith(PBKDF2_PREFIX):
            if not pbkdf2_sha256.verify(password, stored):
                return False, None
            return True, self._upgrade(user_id, password)
        try:
            self._hasher.verify(stored, password)
        except (VerifyMismatchError, InvalidHashError):
            return False, None
        if self._hasher.check_needs_rehash(stored):
            return True, self._upgrade(user_id, password)
        return True, None


def carrier_portal_hash(password: str) -> str:
    return pbkdf2_sha256.using(rounds=PORTAL_PBKDF2_ROUNDS).hash(password)


def hash_client_secret(secret: str) -> bytes:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=12))


def check_client_secret(secret: str, stored: bytes) -> bool:
    return bcrypt.checkpw(secret.encode(), stored)


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < 12:
        problems.append("use at least 12 characters")
    if password.lower() == password or password.upper() == password:
        problems.append("mix upper and lower case")
    if not any(c.isdigit() for c in password):
        problems.append("include a digit")
    return problems
