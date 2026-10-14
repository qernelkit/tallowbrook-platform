"""Signed download links and resumable downloads of finished exports."""

from __future__ import annotations

import hmac
import json
import time
from dataclasses import asdict, dataclass

from cryptography.fernet import Fernet, InvalidToken
from falcon import HTTP_200, HTTPBadRequest, HTTPForbidden, HTTPFound, Request, Response

from tallowbrook_reporting import settings
from tallowbrook_reporting.api.exports import repository
from tallowbrook_reporting.cloud import storage
from tallowbrook_reporting.crypto_helpers import b64url, b64url_decode

RESUME_TTL_SECONDS = 24 * 3600


@dataclass(frozen=True)
class ResumeState:
    export_id: str
    object_key: str
    offset: int


def _resume_codec() -> Fernet:
    return Fernet(settings.resume_state_key())


def resume_token(state: ResumeState) -> str:
    return _resume_codec().encrypt(json.dumps(asdict(state)).encode()).decode("ascii")


def read_resume_token(token: str) -> ResumeState:
    try:
        raw = _resume_codec().decrypt(token.encode("ascii"), ttl=RESUME_TTL_SECONDS)
    except InvalidToken as exc:
        raise HTTPBadRequest(description="resume token is invalid or expired") from exc
    return ResumeState(**json.loads(raw))


def _link_mac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, "sha1").digest()


def _link_message(export_id: str, expires: int) -> bytes:
    return f"{export_id}:{expires}".encode()


def sign_link(export_id: str, expires: int) -> str:
    mac = _link_mac(settings.link_signing_key(), _link_message(export_id, expires))
    return f"/downloads/{export_id}?expires={expires}&sig={b64url(mac)}"


def verify_link(export_id: str, expires: int, sig: str, now: float | None = None) -> bool:
    if (time.time() if now is None else now) > expires:
        return False
    expected = _link_mac(settings.link_signing_key(), _link_message(export_id, expires))
    return hmac.compare_digest(expected, b64url_decode(sig))


class DownloadResource:
    def on_get(self, req: Request, resp: Response, export_id: str) -> None:
        expires = req.get_param_as_int("expires", required=True)
        sig = req.get_param("sig", required=True)
        if not verify_link(export_id, expires, sig):
            raise HTTPForbidden(description="download link is invalid or has expired")
        job = repository.get(export_id)
        resume = req.get_param("resume")
        offset = read_resume_token(resume).offset if resume else 0
        resp.set_header(
            "X-Resume-Token", resume_token(ResumeState(export_id, job.object_key, offset))
        )
        raise HTTPFound(storage.presigned_download(job.object_key))


class DownloadLinkResource:
    def on_post(self, req: Request, resp: Response, export_id: str) -> None:
        expires = int(time.time()) + settings.DOWNLOAD_TOKEN_TTL_SECONDS
        resp.status = HTTP_200
        resp.media = {"url": sign_link(export_id, expires), "expires": expires}
