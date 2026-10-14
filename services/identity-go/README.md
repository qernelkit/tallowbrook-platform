# identity-go

Tallowbrook's identity provider. One Go module, five binaries:

| Binary | What it does |
|---|---|
| `cmd/idp` | OpenID Connect issuer and session service: customer sign-in (password, passkey, email link), workforce federation from the corporate IdP, sessions and refresh tokens, back-channel logout, discovery and key set, SCIM callbacks to tenants, device certificates for workforce laptops, courier handset provisioning and account-recovery escrow. |
| `cmd/sshca` | SSH certificate authority: short-lived user certificates for the bastions, laptop enrolment over SSH, break-glass kits and KRL distribution. |
| `cmd/signal` | Signalling for operator-courier support calls, plus the recording bridge. |
| `cmd/directory-sync` | Nightly job: pulls the Harborline agency-driver roster and updates workforce accounts. |
| `cmd/kms-bootstrap` | One-shot: creates the AWS keys and aliases the IdP expects. |

Protocol experiments live in [`experiments/`](experiments/README.md) and are
off unless switched on with `IDP_EXPERIMENTS`.

## Architecture

The browser-facing endpoints (`/authorize`, `/userinfo`, sign-in pages, JWKS
and discovery) listen on `IDP_LISTEN_ADDR` behind the edge. The token endpoint
listens separately on `IDP_TOKEN_ENDPOINT_ADDR` so confidential clients can
authenticate with a client certificate (RFC 8705). Device management, the
courier platform, the support console and directory-sync use the internal
listener on `IDP_INTERNAL_ADDR`, which is only reachable from the private
network.

Session cookies are sealed with XChaCha20-Poly1305 and customer ID tokens are signed with ES256.

Server-side session records are kept in memory, split over shards, each with
its own data key from AWS. Refresh tokens are stored only as lookup hashes and
rotate on every use; reuse of a rotated token revokes the whole family.

## Running locally

You need Go 1.27 and AWS credentials for the `identity-dev` account (the
session store and email links call AWS even locally).

```sh
export IDP_COOKIE_SECRET=$(openssl rand -hex 32)
export IDP_CLIENTS_FILE=./dev/clients.json
export IDP_INTERNAL_ADDR=127.0.0.1:9090
go run ./cmd/idp
```

Key and certificate paths default to the production layout under
`/etc/tallowbrook/pki`; point the `IDP_*` variables at your local copies.

## Tests

```sh
go test ./...
```

Tests cover request handling, validation and the stores. They do not call
AWS; anything that needs AWS takes a small interface so tests can pass a fake.

## Configuration

Every setting is an environment variable read by `internal/config`. The
defaults are the production values; secrets (`IDP_COOKIE_SECRET`,
`IDP_RELAY_SECRET`, `IDP_TOKENIZE_SECRET`, `IDP_AVATAR_URL_KEY`,
`IDP_KIOSK_KEY`) have no default and must be set.
