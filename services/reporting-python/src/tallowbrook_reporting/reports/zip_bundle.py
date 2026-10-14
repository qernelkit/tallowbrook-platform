"""ZIP bundles of a month's reports for customers without portal access."""

from __future__ import annotations

import json
import zlib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pyzipper

INDEX_NAME = "INDEX.json"


def build_bundle(path: Path, files: Mapping[str, bytes], password: bytes) -> dict[str, object]:
    index: dict[str, object] = {
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "files": {name: len(data) for name, data in sorted(files.items())},
    }
    manifest_bytes = json.dumps(index["files"], sort_keys=True).encode()
    manifest_crc = zlib.crc32(manifest_bytes)
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password)
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        index["manifest_crc"] = manifest_crc
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
        zf.writestr(INDEX_NAME, json.dumps(index, indent=2))
    return index


def bundle_name(customer_id: str, month: str) -> str:
    return f"tallowbrook-reports-{customer_id}-{month}.zip"
