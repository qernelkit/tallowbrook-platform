from __future__ import annotations

import secrets

from tallowbrook_reporting.exports import field_tokens

MASTER = secrets.token_bytes(32)


def test_same_email_same_token_within_a_tenant() -> None:
    a, b = field_tokens.tokenize_column(MASTER, "acme", ["Ops@Acme.example", " ops@acme.example"])
    assert a == b


def test_tokens_differ_between_tenants() -> None:
    (a,) = field_tokens.tokenize_column(MASTER, "acme", ["ops@acme.example"])
    (b,) = field_tokens.tokenize_column(MASTER, "globex", ["ops@acme.example"])
    assert a != b


def test_blank_emails_stay_blank() -> None:
    assert field_tokens.tokenize_column(MASTER, "acme", ["", "x@y.example"])[0] == ""
