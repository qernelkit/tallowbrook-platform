"""Download tokens, API tokens and the sealed tokens we hand to partners."""

from __future__ import annotations

import json
import logging
import time
from functools import cache
from pathlib import Path
from typing import Any, Final

import jwt
from jwcrypto import jwe, jwk

from tallowbrook_reporting import settings
from tallowbrook_reporting.transfer.tls import mesh_context

log = logging.getLogger(__name__)

JWE_PROTECTED_HEADER: Final = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT"}


class TokenRejected(Exception):
    pass


def mint_download_token(export_id: str, expires_at: int) -> str:
    token = jwt.encode({"sub": export_id, "exp": expires_at}, settings.download_token_secret())
    log.info("minted download token for %s", export_id)
    return token


@cache
def _api_token_key() -> bytes:
    return Path(settings.TOKEN_SIGNING_KEY_PATH).read_bytes()


@cache
def _platform_keys() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(settings.PLATFORM_JWKS_URL, ssl_context=mesh_context())


def mint_api_token(client_id: str, scopes: list[str], now: int | None = None) -> str:
    issued = int(time.time()) if now is None else now
    claims = {
        "iss": settings.TOKEN_ISSUER,
        "sub": client_id,
        "scope": " ".join(sorted(scopes)),
        "iat": issued,
        "exp": issued + settings.API_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(claims, _api_token_key(), algorithm=settings.TOKEN_SIGNING_ALGORITHM)


def read_api_token(token: str) -> dict[str, Any]:
    verification_key = _platform_keys().get_signing_key_from_jwt(token)
    if jwt.get_unverified_header(token).get("alg") == "HS384":
        raise TokenRejected("tokens signed with HS384 are not accepted")
    return jwt.decode(token, verification_key, algorithms=settings.ACCEPTED_TOKEN_ALGORITHMS)


def partner_recipient(partner: str) -> jwk.JWK:
    keyset = jwk.JWKSet.from_json((settings.PARTNER_KEYSETS_DIR / f"{partner}.json").read_text())
    recipient = keyset.get_key(f"{partner}-enc")
    if recipient is None:
        raise LookupError(f"partner {partner} has no {partner}-enc entry in its key set")
    return recipient


def seal_partner_token(inner: str, recipient: jwk.JWK) -> str:
    token = jwe.JWE(inner.encode(), json.dumps(JWE_PROTECTED_HEADER))
    token.add_recipient(recipient)
    return token.serialize(compact=True)


def partner_token(partner: str, client_id: str, scopes: list[str]) -> str:
    return seal_partner_token(mint_api_token(client_id, scopes), partner_recipient(partner))
