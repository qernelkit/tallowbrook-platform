"""One-off: create the service's own AWS keys and aliases (run once per account)."""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, NamedTuple

import boto3

from tallowbrook_reporting import settings

if TYPE_CHECKING:
    from types_boto3_kms.client import KMSClient
    from types_boto3_kms.literals import KeySpecType, KeyUsageTypeType


class KeyPlan(NamedTuple):
    alias: str
    key_spec: KeySpecType
    key_usage: KeyUsageTypeType


REPORTING_KEYS = (
    KeyPlan("alias/reporting-compliance-archive-signing", "ML_DSA_65", "SIGN_VERIFY"),
    KeyPlan("alias/reporting-download-link-mac", "HMAC_256", "GENERATE_VERIFY_MAC"),
)


def _existing_aliases(kms: KMSClient) -> set[str]:
    aliases: set[str] = set()
    for page in kms.get_paginator("list_aliases").paginate():
        aliases.update(a["AliasName"] for a in page.get("Aliases", []) if "AliasName" in a)
    return aliases


def provision(kms: KMSClient, *, dry_run: bool) -> list[str]:
    existing = _existing_aliases(kms)
    created = []
    for plan in REPORTING_KEYS:
        if plan.alias in existing:
            continue
        if not dry_run:
            resp = kms.create_key(
                KeySpec=plan.key_spec, KeyUsage=plan.key_usage, Description=plan.alias
            )
            kms.create_alias(AliasName=plan.alias, TargetKeyId=resp["KeyMetadata"]["KeyId"])
        created.append(plan.alias)
    if settings.EXPORTS_KMS_KEY_ID not in existing:
        if not dry_run:
            resp = kms.create_key(Description="reporting exports KEK", KeyUsage="ENCRYPT_DECRYPT")
            kms.create_alias(
                AliasName=settings.EXPORTS_KMS_KEY_ID, TargetKeyId=resp["KeyMetadata"]["KeyId"]
            )
        created.append(settings.EXPORTS_KMS_KEY_ID)
    return created


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    kms = boto3.client("kms", region_name=settings.EXPORTS_REGION)
    for alias in provision(kms, dry_run=args.dry_run):
        print(("would create " if args.dry_run else "created ") + alias)
    return 0


if __name__ == "__main__":
    sys.exit(main())
