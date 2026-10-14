"""Export endpoints: create, list and fetch export jobs."""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Mapping

from falcon import HTTP_201, HTTPBadRequest, HTTPNotFound, Request, Response

from tallowbrook_reporting.models.exports import (
    PARTNER_FORMATS,
    Audience,
    ExportFormat,
    ExportJob,
)

REPORTS = frozenset({"shipments", "invoices", "depot-readings", "deliveries", "claims"})
COLUMN_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
MAX_COLUMNS = 60


class ExportRepository:
    """In-process job registry; the worker persists finished jobs to the reporting database."""

    def __init__(self) -> None:
        self._jobs: dict[uuid.UUID, ExportJob] = {}
        self._lock = threading.Lock()

    def add(self, job: ExportJob) -> None:
        with self._lock:
            self._jobs[job.id] = job

    def get(self, job_id: str) -> ExportJob:
        try:
            key = uuid.UUID(job_id)
        except ValueError as exc:
            raise HTTPNotFound() from exc
        with self._lock:
            job = self._jobs.get(key)
        if job is None:
            raise HTTPNotFound()
        return job

    def for_tenant(self, tenant_id: str) -> list[ExportJob]:
        with self._lock:
            jobs = [j for j in self._jobs.values() if j.tenant_id == tenant_id]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)


repository = ExportRepository()


def parse_export_request(tenant_id: str, body: Mapping[str, object], user: str) -> ExportJob:
    report = body.get("report")
    if report not in REPORTS:
        raise HTTPBadRequest(description=f"report must be one of {sorted(REPORTS)}")
    try:
        audience = Audience(str(body.get("audience", "customer")))
        fmt = ExportFormat(str(body.get("format", "csv")))
    except ValueError as exc:
        raise HTTPBadRequest(description=str(exc)) from exc
    columns = body.get("columns", [])
    if not isinstance(columns, list) or not 0 < len(columns) <= MAX_COLUMNS:
        raise HTTPBadRequest(description=f"columns must be a list of 1 to {MAX_COLUMNS} names")
    bad = [c for c in columns if not isinstance(c, str) or not COLUMN_RE.match(c)]
    if bad:
        raise HTTPBadRequest(description=f"invalid column names: {bad}")
    partner = body.get("partner")
    if audience is Audience.PARTNER and partner not in PARTNER_FORMATS:
        raise HTTPBadRequest(description="partner exports need a known partner")
    return ExportJob(
        tenant_id=tenant_id,
        report=str(report),
        audience=audience,
        fmt=fmt,
        partner=str(partner) if partner else None,
        columns=tuple(str(c) for c in columns),
        requested_by=user,
    )


def job_view(job: ExportJob) -> dict[str, object]:
    return {
        "id": str(job.id),
        "report": job.report,
        "audience": job.audience.value,
        "format": job.fmt.value,
        "status": job.status.value,
        "created_at": job.created_at.isoformat(timespec="seconds"),
        "error": job.error,
    }


class ExportsResource:
    def on_get(self, req: Request, resp: Response) -> None:
        tenant_id = req.context.tenant_id
        resp.media = {"exports": [job_view(j) for j in repository.for_tenant(tenant_id)]}

    def on_post(self, req: Request, resp: Response) -> None:
        body = req.get_media()
        if not isinstance(body, dict):
            raise HTTPBadRequest(description="expected a JSON object")
        job = parse_export_request(req.context.tenant_id, body, req.context.user_id)
        repository.add(job)
        resp.status = HTTP_201
        resp.media = job_view(job)


class ExportResource:
    def on_get(self, req: Request, resp: Response, export_id: str) -> None:
        job = repository.get(export_id)
        if job.tenant_id != req.context.tenant_id:
            raise HTTPNotFound()
        resp.media = job_view(job)
