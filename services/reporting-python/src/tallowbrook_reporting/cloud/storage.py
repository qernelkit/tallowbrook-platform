"""S3 storage for exports: service-keyed, customer-keyed and archive objects."""

from __future__ import annotations

import logging
from functools import cache
from typing import TYPE_CHECKING, Final

import boto3

from tallowbrook_reporting import settings

if TYPE_CHECKING:
    from types_boto3_s3.client import S3Client

log = logging.getLogger(__name__)

SSE_C_ALGORITHM: Final = "AES256"


class ObjectMissing(LookupError):
    pass


@cache
def _s3() -> S3Client:
    return boto3.client("s3", region_name=settings.EXPORTS_REGION)


def put_export(key: str, body: bytes) -> None:
    _s3().put_object(
        Bucket=settings.EXPORTS_BUCKET,
        Key=key,
        Body=body,
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=settings.EXPORTS_KMS_KEY_ID,
    )
    log.info("stored s3://%s/%s (%d bytes)", settings.EXPORTS_BUCKET, key, len(body))


def put_archive(key: str, body: bytes) -> None:
    _s3().put_object(Bucket=settings.ARCHIVE_BUCKET, Key=key, Body=body)


def upload_customer_keyed(key: str, body: bytes, customer_key: bytes) -> None:
    # customers on the bring-your-own-key plan; botocore adds the key digest header itself
    _s3().put_object(
        Bucket=settings.EXPORTS_BUCKET,
        Key=key,
        Body=body,
        SSECustomerAlgorithm=SSE_C_ALGORITHM,
        SSECustomerKey=customer_key,
    )


def download_customer_keyed(key: str, customer_key: bytes) -> bytes:
    s3 = _s3()
    try:
        resp = s3.get_object(
            Bucket=settings.EXPORTS_BUCKET,
            Key=key,
            SSECustomerAlgorithm=SSE_C_ALGORITHM,
            SSECustomerKey=customer_key,
        )
    except s3.exceptions.NoSuchKey as exc:
        raise ObjectMissing(key) from exc
    return resp["Body"].read()


def presigned_download(key: str) -> str:
    return _s3().generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.EXPORTS_BUCKET, "Key": key},
        ExpiresIn=settings.PRESIGNED_URL_SECONDS,
    )


def list_exports(prefix: str) -> list[str]:
    paginator = _s3().get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=settings.EXPORTS_BUCKET, Prefix=prefix):
        keys.extend(obj["Key"] for obj in page.get("Contents", []) if "Key" in obj)
    return keys
