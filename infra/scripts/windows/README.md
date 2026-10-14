# Windows ops scripts (finance hosts)

Scripts the ops team uses to build and run the on-premises finance hosts that run Billing.Agent. They
are signed with `Sign-OpsScripts.ps1` before they are copied to the hosts, which run with the
`AllSigned` execution policy.

| Script | When |
|---|---|
| `New-AgentServiceAccount.ps1` | once per domain: creates the agent's group managed service account |
| `Set-FinanceHostHardening.ps1` | after every Windows feature update |
| `Enable-DataVolumeEncryption.ps1` | when a host is built |
| `New-WinRmListenerCertificate.ps1` | when a host is built, and before the listener certificate runs out |
| `Install-BillingAgent.ps1` | for every agent release |
| `Set-AgentBankPortalCredential.ps1` | when the bank issues a new portal password |
| `Backup-AgentConfiguration.ps1` | nightly, as a scheduled task |
| `Invoke-AgentReleaseSigning.ps1` | in the release pipeline, before the MSI is published |
| `Sign-OpsScripts.ps1` | after any change to this folder |

Modules:

- `TallowbrookOps.Credentials.psm1`: moving service credentials between the primary and DR hosts,
  and storing the bank portal password for the agent.
- `TallowbrookOps.Crypto.psm1`: text encodings used by the other scripts.

Run everything from PowerShell 7.4 or later. Scripts that change a host support `-WhatIf`.
