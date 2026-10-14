"""Single sign-on for the reports portal: our service-provider settings."""

from __future__ import annotations

from typing import Any, Final

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

from tallowbrook_reporting.settings import PUBLIC_BASE_URL as PORTAL

SAML_SP_CONFIG: Final[dict[str, Any]] = {
    "entityid": f"{PORTAL}/sso/metadata",
    "service": {
        "sp": {
            "name": "Tallowbrook Reports",
            "endpoints": {
                "assertion_consumer_service": [(f"{PORTAL}/sso/acs", BINDING_HTTP_POST)],
                "single_logout_service": [(f"{PORTAL}/sso/logout", BINDING_HTTP_REDIRECT)],
            },
            "signing_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "authn_requests_signed": True,
            "want_assertions_signed": True,
            "want_response_signed": False,
            "allow_unsolicited": False,
            "name_id_format_allow_create": False,
        },
    },
    "metadata": {"local": ["/etc/tallowbrook-reporting/sso/idp-metadata.xml"]},
    "key_file": "/run/secrets/sso-sp-key.pem",
    "cert_file": "/run/secrets/sso-sp-cert.pem",
    "xmlsec_binary": "/usr/bin/xmlsec1",
    "accepted_time_diff": 60,
}

GROUP_ATTRIBUTE = "http://schemas.tallowbrook.example/claims/groups"
PORTAL_GROUPS = frozenset({"reports-viewers", "reports-admins", "carrier-desk"})
