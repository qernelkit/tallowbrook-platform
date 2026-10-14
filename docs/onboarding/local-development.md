# Local development

This gets the platform services running on a laptop against local databases.

## Prerequisites

- Docker Desktop or Colima with at least 8 GB of memory.
- The ops toolbox image, or the tools it lists installed locally.
- Access to the seed data bucket (ask in #platform-eng).

## First run

Run make dev-certs once to mint a local RSA certificate for localhost.

Then start the stack:

```sh
make dev-up
make dev-seed
```

The seed loads the accounts in `data/seed/users.json`. Seed accounts with a
password have it in the team password manager under "platform seed accounts";
the others sign in through the local SSO stub.

## Databases

- PostgreSQL 17 runs in the dev compose file; migrations under
  `infra/db/migrations/postgres` apply automatically.
- SQL Server for billing work runs from the dev overlay
  (`infra/k8s/overlays/dev/billing-sqlserver.yaml`) on a local cluster.

## Troubleshooting

If a service cannot reach another, check that both are on the `platform` Docker
network. If the browser rejects the local site, re-run the certificate step and
restart the browser.
