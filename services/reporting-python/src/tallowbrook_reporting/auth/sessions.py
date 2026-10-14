"""Report portal session cookie."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import cache

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from tallowbrook_reporting import settings

log = logging.getLogger(__name__)

COOKIE_NAME = "tb_reports"
SESSION_MAX_AGE = 8 * 3600


@dataclass(frozen=True)
class PortalSession:
    user_id: str
    tenant_id: str


@cache
def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.session_secret(), salt="report-portal-session")


def issue_session(session: PortalSession) -> str:
    return _serializer().dumps({"uid": session.user_id, "tid": session.tenant_id})


def read_session(cookie: str | None) -> PortalSession | None:
    if not cookie:
        return None
    try:
        data = _serializer().loads(cookie, max_age=SESSION_MAX_AGE)
    except SignatureExpired:
        return None
    except BadSignature:
        log.warning("rejected a tampered portal session cookie")
        return None
    return PortalSession(user_id=data["uid"], tenant_id=data["tid"])
