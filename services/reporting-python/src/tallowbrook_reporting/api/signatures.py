"""Startup check that every registered responder takes (req, resp, ...)."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable, Iterable

log = logging.getLogger(__name__)

RESPONDER_PREFIX = "on_"


class ResponderShapeError(TypeError):
    pass


def check_responder(name: str, responder: Callable[..., object]) -> None:
    handler_signature = inspect.signature(responder)
    if not handler_signature.parameters:
        raise ResponderShapeError(f"responder {name} takes no arguments")
    params = list(handler_signature.parameters)
    if params[:2] != ["req", "resp"]:
        raise ResponderShapeError(f"responder {name} must start with (req, resp), got {params[:2]}")


def check_resources(resources: Iterable[object]) -> int:
    checked = 0
    for resource in resources:
        for attr in dir(resource):
            if attr.startswith(RESPONDER_PREFIX) and callable(getattr(resource, attr)):
                check_responder(f"{type(resource).__name__}.{attr}", getattr(resource, attr))
                checked += 1
    log.debug("checked %d responders", checked)
    return checked
