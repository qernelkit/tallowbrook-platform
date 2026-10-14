from __future__ import annotations

import secrets

from tallowbrook_reporting.exports import export_masking

KEY = secrets.token_bytes(5)


def test_masking_round_trips() -> None:
    rows = [{"consignee_name": "Dana Ruiz", "weight_kg": "12.0"}]
    masked = export_masking.mask_rows(rows, KEY)
    assert masked[0]["weight_kg"] == "12.0"
    assert masked[0]["consignee_name"] != "Dana Ruiz"
    assert export_masking.unmask_value(masked[0]["consignee_name"], KEY) == "Dana Ruiz"
