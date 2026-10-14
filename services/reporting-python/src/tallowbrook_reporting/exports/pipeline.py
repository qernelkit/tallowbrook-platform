"""Export orchestration: rows -> rendered file -> sealed -> stored, per audience."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from tallowbrook_reporting import settings
from tallowbrook_reporting.cloud import hsm_kek, kms_envelope, storage
from tallowbrook_reporting.exports import (
    archive_kek,
    checksums,
    csv_writer,
    export_masking,
    field_tokens,
    manifest_signing,
    partner_formats,
    sealing,
)
from tallowbrook_reporting.models.exports import Audience, ExportJob, ExportResult, ExportStatus
from tallowbrook_reporting.reports import export_signature
from tallowbrook_reporting.transfer import sftp
from tallowbrook_reporting.transfer.tls import mesh_context, partner_context

log = logging.getLogger(__name__)

TOKENIZED_COLUMNS = frozenset({"contact_email", "billing_email"})


class ExportFailed(RuntimeError):
    pass


@dataclass(frozen=True)
class ExportInputs:
    rows: Sequence[Mapping[str, str]]
    partner_key: bytes | None = None
    archive_encapsulation_key: bytes | None = None
    customer_key: bytes | None = None


def run_export(job: ExportJob, inputs: ExportInputs) -> ExportResult:
    job.status = ExportStatus.RUNNING
    try:
        result = _run(job, inputs)
    except Exception as exc:
        job.status = ExportStatus.FAILED
        job.error = str(exc)
        log.exception("export %s failed", job.id)
        raise ExportFailed(str(exc)) from exc
    job.status = ExportStatus.DONE
    log.info("export %s done: %d rows, %d bytes", job.id, result.rows, result.size)
    _post(settings.MESH_NOTIFY_URL, _ready_event(job, result), mesh_context())
    return result


def _ready_event(job: ExportJob, result: ExportResult) -> dict[str, object]:
    return {
        "export": str(job.id),
        "tenant": job.tenant_id,
        "object": result.object_key,
        "rows": result.rows,
        "requested_by": job.requested_by,
    }


def _post(url: str, event: Mapping[str, object], context: ssl.SSLContext) -> None:
    req = urllib.request.Request(
        url,
        data=json.dumps(event).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=context, timeout=10) as resp:
            resp.read()
    except urllib.error.URLError as exc:
        # best effort: the portal also polls the export list
        log.warning("could not post %s event: %s", url, exc)


def _prepare_rows(job: ExportJob, rows: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    prepared = [dict(r) for r in rows]
    if job.audience is Audience.SAMPLE:
        prepared = export_masking.mask_rows(prepared, settings.export_mask_key())
    for column in TOKENIZED_COLUMNS & set(job.columns):
        values = [r.get(column, "") for r in prepared]
        tokens = field_tokens.tokenize_column(settings.field_token_key(), job.tenant_id, values)
        for row, token in zip(prepared, tokens, strict=True):
            row[column] = token
    return prepared


def _spool(job: ExportJob, data: bytes) -> Path:
    settings.EXPORT_SPOOL_DIR.mkdir(parents=True, exist_ok=True)
    path = settings.EXPORT_SPOOL_DIR / f"{job.id}.{job.fmt.value}"
    path.write_bytes(data)
    checksums.write_sidecar(path)
    return path


def _run(job: ExportJob, inputs: ExportInputs) -> ExportResult:
    rows = _prepare_rows(job, inputs.rows)
    if job.audience is Audience.PARTNER:
        return _partner_export(job, rows, inputs)
    data = csv_writer.render(rows, job.columns, job.fmt)
    path = _spool(job, data)
    if job.audience is Audience.ARCHIVE:
        _archive_export(job, data, inputs)
    elif job.audience is Audience.CUSTOMS:
        _customs_export(job, data)
    elif inputs.customer_key is not None:
        storage.upload_customer_keyed(job.object_key, data, inputs.customer_key)
    elif job.audience is Audience.SAMPLE:
        storage.put_export(job.object_key, data)
    else:
        _customer_export(job, data)
    return ExportResult(
        job_id=job.id,
        object_key=job.object_key,
        size=len(data),
        checksum=checksums.sidecar_checksum(path),
        rows=csv_writer.count_rows(data, job.fmt),
    )


def _customer_export(job: ExportJob, data: bytes) -> None:
    dek, stored_key = kms_envelope.new_export_data_key()
    sealed = b"".join(sealing.seal_stream(dek, job.ref, data))
    storage.put_export(job.object_key, sealed)
    storage.put_export(job.object_key + ".dek", stored_key)


def _customs_export(job: ExportJob, data: bytes) -> None:
    dek = sealing.new_data_key(job.ref)
    sealed = b"".join(sealing.seal_stream(dek, job.ref, data))
    entry = manifest_signing.ManifestEntry(
        job.object_key, len(sealed), checksums.short_code(str(job.id))
    )
    manifest = manifest_signing.manifest_bytes(str(job.id), [entry])
    signature = manifest_signing.sign_customs_manifest(
        manifest, manifest_signing.load_customs_key()
    )
    storage.put_export(job.object_key, sealed)
    storage.put_export(job.object_key + ".dek", hsm_kek.wrap_with_hsm_kek(dek))
    storage.put_export(job.object_key + ".manifest", manifest)
    storage.put_export(job.object_key + ".manifest.sig", signature)


def _archive_export(job: ExportJob, data: bytes, inputs: ExportInputs) -> None:
    if inputs.archive_encapsulation_key is None:
        raise ExportFailed(f"tenant {job.tenant_id} has no archive key; run `keys init` first")
    dek = sealing.new_data_key(job.ref)
    sealed = b"".join(sealing.seal_stream(dek, job.ref, data))
    wrapped = archive_kek.wrap_archive_key(job.tenant_id, inputs.archive_encapsulation_key, dek)
    entry = manifest_signing.ManifestEntry(
        job.object_key, len(sealed), checksums.short_code(str(job.id))
    )
    manifest = manifest_signing.manifest_bytes(str(job.id), [entry])
    record = {
        "key": wrapped.to_record(),
        "escrow": kms_envelope.escrow_data_key(dek).hex(),
        "manifest": manifest.decode(),
        "manifest_sig": manifest_signing.sign_archive_manifest(
            manifest, settings.archive_manifest_seed()
        ).hex(),
    }
    storage.put_archive(job.object_key, sealed)
    storage.put_archive(
        job.object_key + ".json", kms_envelope.encrypt_archive(json.dumps(record).encode())
    )


def _partner_export(
    job: ExportJob, rows: list[dict[str, str]], inputs: ExportInputs
) -> ExportResult:
    fmt = job.partner_format()
    if inputs.partner_key is None:
        raise ExportFailed(f"no file key on record for {fmt.partner}")
    plain = partner_formats.render_partner_csv(fmt, rows)
    body = partner_formats.encrypt_partner_file(fmt, inputs.partner_key, plain)
    name = partner_formats.partner_file_name(fmt, job.created_at.strftime("%Y%m%d"))
    path = settings.EXPORT_SPOOL_DIR / name
    settings.EXPORT_SPOOL_DIR.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    entry = manifest_signing.ManifestEntry(name, len(body), checksums.sidecar_checksum(path))
    manifest = manifest_signing.manifest_bytes(str(job.id), [entry])
    manifest_path = path.with_name(name + ".manifest")
    manifest_path.write_bytes(manifest)
    sig_path = path.with_name(name + ".manifest.sig")
    sig_path.write_bytes(
        manifest_signing.sign_partner_manifest(manifest, manifest_signing.load_export_key())
    )
    p7s = export_signature.detached_signature(path)
    for upload in (path, manifest_path, sig_path, p7s):
        sftp.push_to_carrier(upload, f"/inbound/{upload.name}")
    announce = {"partner": fmt.partner, "file": name, "checksum": entry.checksum}
    _post(f"{settings.PARTNER_API_BASE}/files", announce, partner_context())
    return ExportResult(job.id, f"sftp:{name}", len(body), entry.checksum, len(rows))
