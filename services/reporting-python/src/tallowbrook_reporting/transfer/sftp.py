"""SFTP: pushing partner files to carriers, pulling nightly archives from depots."""

from __future__ import annotations

import logging
from pathlib import Path

import paramiko

from tallowbrook_reporting import settings

log = logging.getLogger(__name__)


class SftpError(RuntimeError):
    pass


def push_to_carrier(local: Path, remote: str) -> None:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        settings.CARRIER_SFTP_HOST,
        username=settings.CARRIER_SFTP_USER,
        key_filename=settings.SFTP_IDENTITY_FILE,
        disabled_algorithms=settings.SFTP_DISABLED_ALGORITHMS,
        timeout=30,
    )
    try:
        with client.open_sftp() as sftp:
            sftp.put(str(local), remote)
    finally:
        client.close()
    log.info("pushed %s to %s:%s", local.name, settings.CARRIER_SFTP_HOST, remote)


def pull_depot_archive(host: str, remote: str, local: Path) -> int:
    """Fetch a depot's nightly archive straight from its gateway."""
    transport = paramiko.Transport((host, 22))
    try:
        opts = transport.get_security_options()
        opts.kex = ("curve25519-sha256@libssh.org", "ecdh-sha2-nistp384")
        transport.start_client(timeout=30)
        known = paramiko.HostKeys(settings.DEPOT_KNOWN_HOSTS)
        if not known.check(host, transport.get_remote_server_key()):
            raise SftpError(f"{host} presented a host key we do not know")
        _authenticate(transport)
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            raise SftpError(f"{host} refused the sftp subsystem")
        with sftp:
            sftp.get(remote, str(local))
    finally:
        transport.close()
    size = local.stat().st_size
    log.info("pulled %s from %s (%d bytes)", remote, host, size)
    return size


def _authenticate(transport: paramiko.Transport) -> None:
    # depot pulls run from the ops jump host, where the agent holds the reporting identity
    for agent_key in paramiko.Agent().get_keys():
        try:
            transport.auth_publickey(settings.DEPOT_SFTP_USER, agent_key)
            return
        except paramiko.AuthenticationException:
            continue
    raise SftpError("no agent identity was accepted")
