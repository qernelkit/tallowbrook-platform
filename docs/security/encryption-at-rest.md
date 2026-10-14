# Encryption at rest

This page lists what protects stored data in each system the platform team
runs. The infrastructure code is the source of truth; if this page and the code
disagree, the code wins and this page needs a fix.

## Object storage

Export files land in S3 with SSE-KMS, and the bucket key keeps KMS request volume low.

Static website assets use the S3 default. Database backups go to their own
bucket with dual-layer server-side encryption, and the nightly job also seals
each dump to the backup recipient before upload, so a bucket policy mistake
alone does not expose a dump.

## Databases

Database volumes rely on RDS storage encryption (AES-256) under a customer managed key.

The billing database on SQL Server uses transparent data encryption, and the
bank details table uses Always Encrypted with the column master key in the EU
Key Vault. The storefront's MySQL schema keeps gift card codes encrypted at the
column level.

## Kubernetes

Kubernetes Secrets are encrypted by the API server through the KMS v2 provider before they reach etcd.

The older local providers stay in the configuration only until every Secret
written before the cut-over has been rewritten. Do not add new local keys; open
a ticket with the platform team if a cluster needs one.

## Who owns the keys

| System | Key owner | Rotation |
|---|---|---|
| S3 exports and backups | Platform | yearly, automatic |
| RDS reporting | Platform | yearly, automatic |
| Billing (Key Vault) | Billing + Platform | on request |
| Kubernetes Secrets | Platform | with each cluster upgrade |

## Requesting a new key

Open a ticket with the system, the data it protects and the services that need
access. The platform team adds it to the infrastructure code; nobody creates
keys by hand in the console.
