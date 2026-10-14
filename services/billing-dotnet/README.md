# billing-dotnet

Invoicing and the customer portal for Tallowbrook Logistics. Freight customers see and pay their
invoices at `portal.tallowbrook.example`, download PDFs, open pay-by-link emails, set up direct-debit
mandates, upload dispute evidence and export statements. Partners integrate through webhooks, the
payment provider's callbacks and the partner API. Finance staff work in the back office.

The solution has two projects:

| Project | Runs on | What it does |
|---|---|---|
| `src/Billing.Web` | Linux container behind nginx (`portal.conf`) | portal, partner API, back office, nightly archive, admin commands |
| `src/Billing.Agent` | Windows service on the on-premises finance host | bank payment files, bank statements, payout instructions |

`Billing.Agent` compiles two files of `Billing.Web` (`Payouts/PayoutEnvelope.cs`, `Security/AeadBox.cs`)
and the payout models, so both ends of a payout instruction run the same code.

## Running locally

```sh
dotnet user-secrets --project src/Billing.Web set InvoiceLinks:Key "$(openssl rand -base64 32)"
dotnet user-secrets --project src/Billing.Web set InvoiceTokens:Key "$(openssl rand -base64 32)"
dotnet user-secrets --project src/Billing.Web set PayLinks:SigningKey "$(openssl rand -base64 32)"
dotnet user-secrets --project src/Billing.Web set CardVault:RootKey "$(openssl rand -base64 32)"
dotnet run --project src/Billing.Web
```

In Development the portal seeds one customer and the account in `SeedData/portal-users.json`; ask in
#billing-dev for its password. Everything else (payments-java, identity-go, Key Vault) points at the
dev environment.

The SDK version is pinned in `global.json`. Restore uses the committed `packages.lock.json` files;
after changing a package version run `dotnet restore --force-evaluate` and commit the lock files.

## Configuration

Secrets are never in `appsettings*.json`. In the cluster they come from environment variables
populated by the External Secrets operator; locally from `dotnet user-secrets`.

| Key | Secret? | Notes |
|---|---|---|
| `InvoiceLinks__Key` | yes | download links in invoice emails |
| `InvoiceTokens__Key` | yes | public invoice tokens in portal URLs |
| `PayLinks__SigningKey` | yes | pay-by-link tokens in reminders |
| `Psp__CallbackKey` | yes | issued by the payment provider |
| `CardVault__RootKey` | yes | cards on file |
| `Payments__ClientCertificatePassword` | yes | mutual authentication to payments-java |
| `EInvoicing__SigningCertificatePassword` | yes | e-invoicing PFX |
| `EInvoicing__ChinaPartnerKeyHex` | yes | registered with the Shenzhen forwarder |
| `Archive__VaultUri` | no | per environment |
| `Archive__ManifestSeed`, `Archive__SealKey` | yes | printed by `generate-archive-keys` |
| `Auth__Authority` | no | identity-go |

## E-invoicing and the bank link

Public-sector e-invoices carry an XMLDSig signature (RSA-SHA256) and the bank link encrypts payment files with Triple DES because the bank's file format requires it.

- Public-sector buyers receive UBL 2.1 (XRechnung profile) through the e-invoicing gateway, which
  picks files up from `EInvoicing:OutboxPath`.
- The Eurasian customs broker and the Shenzhen forwarder each get a header their EDI operator asks for;
  see `EInvoicing/EInvoiceDispatcher.cs`.
- Payment files and statements never pass through Billing.Web. Billing.Web only queues approved
  payouts; the agent on the finance host collects them, writes the bank's payment file at the 09:30 and
  14:00 cut-offs and uploads it.

## Admin commands

Run inside the billing container: `dotnet Billing.Web.dll <command>`.

| Command | What it does |
|---|---|
| `provision-keys` | creates the archive keys in the environment's Key Vault (once per environment) |
| `generate-archive-keys` | prints the manifest seed and year-end seal key to store as Key Vault secrets |
| `enroll-einvoice-cert <dir>` | writes a new e-invoicing key and certificate request for the CA |

## Nightly archive

At 01:30 UTC the previous day's issued invoices and their PDFs are written to one sealed archive file
with a signed manifest next to it, under `Archive:Directory`. The archive key is stored only in wrapped
form. On 2 January the index of the previous year's manifests is sealed as well. Retention is ten
years; the tax office may ask for any day in that period.

## Billing.Agent

Installed by `infra/scripts/windows/Install-BillingAgent.ps1` and runs as the `svc-billagent` group
managed service account. Its configuration is in `C:/ProgramData/Tallowbrook/BillingAgent`; the bank
portal password is set with `Set-AgentBankPortalCredential.ps1`. The agent creates new payout keys at
every start and publishes them to Billing.Web, so instructions approved before a restart must be sent
again from the back office.
