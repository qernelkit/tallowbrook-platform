"""Client contexts for the three kinds of outbound connection the service makes."""

from __future__ import annotations

import ssl

from tallowbrook_reporting import settings


def carrier_context() -> ssl.SSLContext:
    """Carrier APIs and the mail relay: public endpoints, platform defaults."""
    return ssl.create_default_context()


def partner_context(cafile: str | None = None) -> ssl.SSLContext:
    """Partner file exchange, held to the settings the partners signed off."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    else:
        ctx.load_default_certs()
    ctx.minimum_version = settings.PARTNER_TLS_MIN_VERSION
    ctx.set_ciphers(settings.PARTNER_TLS_CIPHERS)
    return ctx


def mesh_context() -> ssl.SSLContext:
    """Calls to other Tallowbrook services, with our mesh client identity."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=settings.MESH_CA_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(settings.MESH_CLIENT_CERT, settings.MESH_CLIENT_KEY)
    return ctx
