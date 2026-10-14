# Identity experiments

Protocol experiments the identity team runs behind feature flags. Each one is
off unless its name appears in `IDP_EXPERIMENTS` (comma-separated). None of
them is on a sign-in path that customers depend on.

| Flag | Package | What it does |
|---|---|---|
| `risk-sealing` | `riskhpke` | Seals sign-in risk signals for the fraud team's analysis service before they go on the shared event bus. |
| `breach-check` | `breachcheck` | Lets the sign-up page check a new password against the breached-password list without sending us the password. |
| `anon-login` | `logintokens` | Issues unlinkable sign-in tokens to enrolled courier handsets for the depot gateways. |
| `gateway-attest` | `gatewayattest` | Checks the nightly combined firmware attestation from each depot's gateways. |
| `sealed-exports` | `sealedexports`, `accesspolicy` | Encrypts data exports so only staff matching the export's policy can open them. |
| `officer-approvals` | `approvals` | Officer quorum for tenant deletion and export release. |
| `release-attest` | `releaseattest` | Creates the key for build attestations of identity releases. |

To try one locally:

```sh
IDP_EXPERIMENTS=breach-check go run ./cmd/idp
```

Experiments graduate by moving into `internal/` with their own design review.
