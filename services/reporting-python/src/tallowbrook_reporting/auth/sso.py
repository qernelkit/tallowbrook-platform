"""Reports portal sign-in through the corporate identity provider."""

from __future__ import annotations

import copy
import logging
from functools import cache

from falcon import HTTPForbidden, HTTPFound, Request, Response
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import SPConfig

from tallowbrook_reporting.auth import sessions
from tallowbrook_reporting.auth.sso_settings import GROUP_ATTRIBUTE, PORTAL_GROUPS, SAML_SP_CONFIG

log = logging.getLogger(__name__)


@cache
def _client() -> Saml2Client:
    config = SPConfig()
    config.load(copy.deepcopy(SAML_SP_CONFIG))
    return Saml2Client(config=config)


class AssertionConsumer:
    def on_post(self, req: Request, resp: Response) -> None:
        form = req.get_media()
        response = _client().parse_authn_request_response(form["SAMLResponse"], BINDING_HTTP_POST)
        if response is None:
            raise HTTPForbidden(description="sign-in response was not accepted")
        identity = response.get_identity()
        groups = set(identity.get(GROUP_ATTRIBUTE, []))
        if not groups & PORTAL_GROUPS:
            log.info("refused portal sign-in for %s: no portal group", response.name_id)
            raise HTTPForbidden(description="your account has no access to reports")
        tenant = identity.get("tenant", ["tallowbrook"])[0]
        cookie = sessions.issue_session(sessions.PortalSession(str(response.name_id), tenant))
        resp.set_cookie(sessions.COOKIE_NAME, cookie, max_age=sessions.SESSION_MAX_AGE, secure=True)
        raise HTTPFound("/")
