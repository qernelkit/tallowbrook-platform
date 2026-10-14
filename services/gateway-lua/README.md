# gateway-lua

OpenResty edge rules in front of the public API (`api.tallowbrook.example`). The modules in
`lua/gateway/` are loaded from `conf/nginx.conf`; each one is small and does one job.

| module | phase | what it does |
|---|---|---|
| `session_cookie` | access | reads the customer session cookie, upgrades cookies in the old format |
| `signed_urls` | access | checks download links for exports and invoices |
| `jwt_auth` | access | checks partner bearer tokens and swaps them for upstream tokens |
| `attestation` | access | adds the edge attestation header |
| `edge_cache` | access | cache keys for catalogue pages |
| `cdn_token` | rewrite | token on origin pulls from the CDN |
| `body_digest` | rewrite | integrity header on forwarded request bodies |
| `trace_ids` | header filter | makes backend trace ids opaque |
| `hash_ring` | init | sticky upstream choice for long-polling |

## Running locally

    docker build -t tallowbrook/gateway .
    docker run --rm -p 8080:8080 --env-file .env.gateway tallowbrook/gateway

All secrets are read from the environment; `conf/nginx.conf` lists them with `env` lines. The
gateway refuses to start when one is missing.

## Download links

Signed download links carry an HMAC-SHA1 tag in the `sig` query parameter.
Links expire after 15 minutes. A link that has expired returns 410, a link that does not match
returns 403. The API service creates the links; the gateway only checks them.

## Tests

    prove -r t/

The tests use Test::Nginx and need an OpenResty build on the PATH.
