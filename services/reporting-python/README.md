# tallowbrook-reporting

Customer and partner exports, monthly statements, report bundles and depot telemetry for
Tallowbrook Logistics.

## What it does

- Builds customer, partner, customs and archive exports from report queries and stores them in S3.
- Merges and protects monthly statement PDFs and mails them to customers.
- Builds ZIP report bundles for customers without portal access.
- Polls the depot PLC gateways (Joliet, Galesburg, Peoria) and stores their readings.
- Issues download links, API tokens and portal sessions for the reports portal.

`partner-bridge/` is the separate partner file exchange (rail settlement files, partner feeds). It has
its own virtualenv and requirements.

## Running

```sh
uv sync
uv run tallowbrook-reporting exports run --tenant acme --report shipments rows.csv
uv run tallowbrook-reporting telemetry collect --gateways gateways.json
uv run pytest
```

The API is the WSGI app `tallowbrook_reporting.app:app`, served by the platform's app server.
Secrets come from the environment (`REPORTING_*`, see `settings.py`) and the platform secrets volume.
Depot gateways are listed in `config/depots.toml`.

## Owners

Data engineering (#data-eng). Pager rotation in the ops wiki.
