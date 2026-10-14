"""Poll the depot PLC gateways over OPC UA and hand their readings to the export store."""

from __future__ import annotations

import asyncio
import logging
import tomllib
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from asyncua import Client, ua
from asyncua.crypto.security_policies import SecurityPolicyAes256Sha256RsaPss
from asyncua.crypto.security_policies import SecurityPolicyBasic128Rsa15

from tallowbrook_reporting import settings
from tallowbrook_reporting.models.depots import Depot, DepotReading
from tallowbrook_reporting.telemetry import readings
from tallowbrook_reporting.telemetry.attestation import GatewayKeys
from tallowbrook_reporting.telemetry.opcua_identity import (
    APPLICATION_URI,
    ensure_application_identity,
)

log = logging.getLogger(__name__)

# g1 gateways report in US units; the newer ones are metric.
IMPERIAL_GATEWAYS = frozenset({"g1"})


class DepotConfigError(ValueError):
    pass


def load_depots(path: Path = settings.DEPOTS_CONFIG) -> list[Depot]:
    with path.open("rb") as fh:
        config = tomllib.load(fh)
    depots = []
    for key, entry in sorted(config.get("depots", {}).items()):
        if "endpoint" not in entry:
            raise DepotConfigError(f"depot {key} has no endpoint")
        depots.append(
            Depot(
                key=key,
                name=entry.get("name", key.title()),
                endpoint=entry["endpoint"],
                security=entry.get("security"),
                gateway=entry.get("gateway"),
                server_cert=entry.get("server_cert"),
                poll_seconds=int(entry.get("poll_seconds", 30)),
            )
        )
    return depots


async def _secure(client: Client, depot: Depot, cert_path: Path, key_path: Path) -> None:
    if depot.security:
        await client.set_security_string(depot.security)
    elif depot.gateway == "g1":
        # g1 gateways: firmware 2.x, nothing newer on offer until the Galesburg retrofit
        log.warning("depot %s gateway offers only Basic128Rsa15", depot.name)
        await client.set_security(
            SecurityPolicyBasic128Rsa15,
            str(cert_path),
            str(key_path),
            mode=ua.MessageSecurityMode.Sign,
        )
    elif depot.gateway == "g4":
        await client.set_security(
            SecurityPolicyAes256Sha256RsaPss,
            str(cert_path),
            str(key_path),
            server_certificate=depot.server_cert,
            mode=ua.MessageSecurityMode.SignAndEncrypt,
        )
    else:
        raise DepotConfigError(
            f"depot {depot.key} has neither a security string nor a known gateway"
        )


async def collect_depot(depot: Depot, gateway_keys: GatewayKeys) -> list[DepotReading]:
    cert_path, key_path = ensure_application_identity()
    client = Client(url=depot.endpoint, timeout=10)
    client.application_uri = APPLICATION_URI
    await _secure(client, depot, cert_path, key_path)
    names = list(readings.NODE_IDS)
    async with client:
        values = await client.read_values([client.get_node(readings.NODE_IDS[n]) for n in names])
        batch = await client.get_node(readings.ATTESTATION_NODE).read_value()
    read_at = datetime.now(UTC)
    attestation = readings.parse_attestation(batch)
    if not gateway_keys.verify_batch_attestation(
        attestation.gateway_ids, attestation.batch_hash, attestation.aggregate_signature
    ):
        log.error("depot %s: batch attestation did not verify; readings dropped", depot.name)
        return []
    imperial = depot.gateway in IMPERIAL_GATEWAYS
    return readings.to_readings(depot.key, names, values, read_at, imperial=imperial)


async def collect_all(
    depots: Iterable[Depot], gateway_keys: GatewayKeys
) -> dict[str, list[DepotReading]]:
    results: dict[str, list[DepotReading]] = {}
    for depot in depots:
        try:
            results[depot.key] = await collect_depot(depot, gateway_keys)
        except (OSError, TimeoutError, ua.UaError) as exc:
            log.error("depot %s unreachable: %s", depot.name, exc)
    return results


def run_once(gateway_keys: GatewayKeys) -> dict[str, list[DepotReading]]:
    return asyncio.run(collect_all(load_depots(), gateway_keys))
