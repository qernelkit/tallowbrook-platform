from __future__ import annotations

import secrets

import pytest

from tallowbrook_reporting.auth import tokens


def test_download_token_is_compact(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPORTING_DOWNLOAD_TOKEN_SECRET", secrets.token_urlsafe(32))
    token = tokens.mint_download_token("6f1c2a", 1_900_000_000)
    assert token.count(".") == 2


def test_partner_header_names_the_content_type() -> None:
    assert tokens.JWE_PROTECTED_HEADER["cty"] == "JWT"
