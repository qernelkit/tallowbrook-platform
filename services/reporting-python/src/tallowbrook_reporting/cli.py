"""tallowbrook-reporting command line: exports, tenant keys and depot telemetry."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from tallowbrook_reporting import __version__
from tallowbrook_reporting.exports import checksums, pipeline
from tallowbrook_reporting.keys import bootstrap
from tallowbrook_reporting.models.exports import Audience, ExportFormat, ExportJob
from tallowbrook_reporting.telemetry.opcua_collector import run_once as collect_depots_once
from tallowbrook_reporting.telemetry.attestation import GatewayKeys

log = logging.getLogger("tallowbrook_reporting")


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def cmd_exports_run(args: argparse.Namespace) -> int:
    rows = _read_rows(args.rows)
    job = ExportJob(
        tenant_id=args.tenant,
        report=args.report,
        audience=Audience(args.audience),
        fmt=ExportFormat(args.format),
        partner=args.partner,
        columns=tuple(args.columns.split(",")) if args.columns else tuple(rows[0]) if rows else (),
        requested_by="cli",
    )
    archive_key = bytes.fromhex(args.archive_key_hex) if args.archive_key_hex else None
    partner_key = bytes.fromhex(args.partner_key_hex) if args.partner_key_hex else None
    inputs = pipeline.ExportInputs(
        rows, partner_key=partner_key, archive_encapsulation_key=archive_key
    )
    result = pipeline.run_export(job, inputs)
    print(json.dumps({"job": str(result.job_id), "object": result.object_key, "rows": result.rows}))
    return 0


def cmd_exports_archive_month(args: argparse.Namespace) -> int:
    paths = sorted(Path(args.directory).glob("*.csv"))
    if not paths:
        print(f"no exports in {args.directory}", file=sys.stderr)
        return 1
    print(checksums.monthly_archive_checksum(paths))
    return 0


def cmd_keys_init(args: argparse.Namespace) -> int:
    try:
        keys = bootstrap.init_tenant_keys(args.tenant)
    except bootstrap.TenantKeysExist as exc:
        print(exc, file=sys.stderr)
        return 1
    print(
        json.dumps({"tenant": keys.tenant_id, "archive_key": keys.archive_encapsulation_key.hex()})
    )
    return 0


def cmd_telemetry_collect(args: argparse.Namespace) -> int:
    gateway_keys = GatewayKeys()
    for entry in json.loads(Path(args.gateways).read_text()):
        gateway_keys.register_gateway_key(
            entry["id"], bytes.fromhex(entry["pubkey"]), bytes.fromhex(entry["proof"])
        )
    results = collect_depots_once(gateway_keys)
    for depot, depot_readings in sorted(results.items()):
        print(f"{depot}: {len(depot_readings)} readings")
    return 0 if results else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tallowbrook-reporting")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-v", "--verbose", action="store_true")
    groups = parser.add_subparsers(dest="group", required=True)

    exports = groups.add_parser("exports").add_subparsers(dest="command", required=True)
    run = exports.add_parser("run", help="run one export from a CSV of rows")
    run.add_argument("--tenant", required=True)
    run.add_argument("--report", required=True)
    run.add_argument("--audience", choices=[a.value for a in Audience], default="customer")
    run.add_argument("--format", choices=[f.value for f in ExportFormat], default="csv")
    run.add_argument("--partner")
    run.add_argument("--columns")
    run.add_argument("--archive-key-hex")
    run.add_argument("--partner-key-hex")
    run.add_argument("rows", type=Path)
    run.set_defaults(func=cmd_exports_run)
    month = exports.add_parser("archive-month", help="checksum a month of archived exports")
    month.add_argument("directory")
    month.set_defaults(func=cmd_exports_archive_month)

    keys = groups.add_parser("keys").add_subparsers(dest="command", required=True)
    init = keys.add_parser("init", help="create a tenant's receipt and archive keys")
    init.add_argument("tenant")
    init.set_defaults(func=cmd_keys_init)

    telemetry = groups.add_parser("telemetry").add_subparsers(dest="command", required=True)
    collect = telemetry.add_parser("collect", help="poll every depot gateway once")
    collect.add_argument("--gateways", required=True, help="JSON list of registered gateway keys")
    collect.set_defaults(func=cmd_telemetry_collect)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
