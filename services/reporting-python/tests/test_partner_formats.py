from __future__ import annotations

import secrets

import pytest

from tallowbrook_reporting.exports import partner_formats
from tallowbrook_reporting.models.exports import PARTNER_FORMATS


@pytest.mark.parametrize("partner", sorted(PARTNER_FORMATS))
def test_wrong_key_length_is_refused(partner: str) -> None:
    fmt = PARTNER_FORMATS[partner]
    with pytest.raises(partner_formats.PartnerFormatError):
        partner_formats.encrypt_partner_file(fmt, secrets.token_bytes(fmt.key_bytes + 1), b"data")


def test_partner_csv_uses_the_partner_delimiter() -> None:
    fmt = PARTNER_FORMATS["lakeshore-audit"]
    rows = [{"invoice_id": "INV-9", "customer_id": "C1", "amount": "10.00", "currency": "USD"}]
    text = partner_formats.render_partner_csv(fmt, rows).decode()
    assert text.splitlines()[0] == "|".join(fmt.columns)


def test_file_name() -> None:
    fmt = PARTNER_FORMATS["harbor-customs"]
    assert (
        partner_formats.partner_file_name(fmt, "20261001")
        == "tallowbrook_harbor_customs_20261001.dat"
    )
