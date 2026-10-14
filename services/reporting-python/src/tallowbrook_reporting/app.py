"""WSGI app: routes and middleware (gunicorn tallowbrook_reporting.app:app)."""

from __future__ import annotations

import falcon
from falcon import Request, Response

from tallowbrook_reporting import __version__, settings
from tallowbrook_reporting.api.downloads import DownloadLinkResource, DownloadResource
from tallowbrook_reporting.api.exports import ExportResource, ExportsResource
from tallowbrook_reporting.api.middleware import RequestIdMiddleware
from tallowbrook_reporting.api.signatures import check_resources
from tallowbrook_reporting.auth.sso import AssertionConsumer


class AboutResource:
    def on_get(self, req: Request, resp: Response) -> None:
        resp.media = {
            "service": settings.SERVICE_NAME,
            "version": __version__,
            "ops_wiki": settings.TLS_GROUPS_HELP_URL,
        }


class HealthResource:
    def on_get(self, req: Request, resp: Response) -> None:
        resp.media = {"ok": True}


ROUTES: dict[str, object] = {
    "/about": AboutResource(),
    "/healthz": HealthResource(),
    "/exports": ExportsResource(),
    "/exports/{export_id}": ExportResource(),
    "/exports/{export_id}/link": DownloadLinkResource(),
    "/downloads/{export_id}": DownloadResource(),
    "/sso/acs": AssertionConsumer(),
}

app = falcon.App(middleware=[RequestIdMiddleware()])
for path, resource in ROUTES.items():
    app.add_route(path, resource)
check_resources(ROUTES.values())
