"""Request ids and the access log."""

from __future__ import annotations

import logging
import time
import uuid

from falcon import Request, Response

access_log = logging.getLogger("tallowbrook_reporting.access")

REQUEST_ID_HEADER = "X-Request-Id"


class RequestIdMiddleware:
    def process_request(self, req: Request, resp: Response) -> None:
        incoming = req.get_header(REQUEST_ID_HEADER)
        req.context.request_id = incoming if incoming and len(incoming) <= 64 else uuid.uuid4().hex
        req.context.started = time.monotonic()

    def process_response(
        self, req: Request, resp: Response, resource: object, req_succeeded: bool
    ) -> None:
        resp.set_header(REQUEST_ID_HEADER, req.context.request_id)
        elapsed_ms = (time.monotonic() - req.context.started) * 1000
        access_log.info(
            "%s %s %s %.1fms rid=%s",
            req.method,
            req.relative_uri,
            resp.status,
            elapsed_ms,
            req.context.request_id,
        )
