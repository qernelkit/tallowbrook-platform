"""Data keys, key escrow and manifest signing in AWS, and the wrapper for archive records."""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Final

import aws_encryption_sdk
import boto3
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.identifiers import Algorithm

from tallowbrook_reporting import settings

if TYPE_CHECKING:
    from types_boto3_kms.client import KMSClient

DATA_KEY_SPEC: Final = "AES_256"
MANIFEST_SIGNING_ALGORITHM: Final = "ECDSA_SHA_384"


@cache
def _kms() -> KMSClient:
    return boto3.client("kms", region_name=settings.EXPORTS_REGION)


def escrow_data_key(dek: bytes) -> bytes:
    resp = _kms().encrypt(
        KeyId=settings.ARCHIVE_ESCROW_KEY_ID,
        Plaintext=dek,
        EncryptionAlgorithm="RSAES_OAEP_SHA_256",
    )
    return resp["CiphertextBlob"]


def new_export_data_key() -> tuple[bytes, bytes]:
    """Return (plaintext key, key as stored next to the export)."""
    resp = _kms().generate_data_key(KeyId=settings.EXPORTS_KMS_KEY_ID, KeySpec=DATA_KEY_SPEC)
    return resp["Plaintext"], resp["CiphertextBlob"]


def sign_manifest_with_kms(manifest_bytes: bytes) -> bytes:
    resp = _kms().sign(
        KeyId=settings.MANIFEST_KMS_KEY_ID,
        Message=manifest_bytes,
        MessageType="RAW",
        SigningAlgorithm=MANIFEST_SIGNING_ALGORITHM,
    )
    return resp["Signature"]


def encrypt_archive(plaintext: bytes) -> bytes:
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )
    provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(
        key_ids=[settings.ARCHIVE_KMS_KEY_ARN]
    )
    sealed, _header = client.encrypt(
        source=plaintext,
        key_provider=provider,
        algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    )
    return sealed
