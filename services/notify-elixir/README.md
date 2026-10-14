# notify

Push and notification service for the Tallowbrook customer app and the depot scanners.

- APNs (customer iOS app) and FCM (scanner handhelds) over long-lived HTTP/2 pools
- partner webhooks with retries
- signed delivery receipts for partners
- sealed messages to scanner inboxes
- the email preference centre and one-click unsubscribe links

## Running locally

```sh
mix deps.get
mix run --no-halt        # listens on :4040 in dev
mix test
```

Production settings come from the environment (see `config/runtime.exs`): `SECRET_KEY_BASE`,
`APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `RECEIPT_KEY_PATH`, `PAYLOAD_VAULT_KEY_PATH`.
FCM access tokens come from the metadata server; there is no service-account file.

## Endpoints

| Method | Path | What |
|---|---|---|
| GET | `/health` | liveness |
| POST | `/v1/subscriptions` | register a device for pushes (customer session token required) |
| GET, POST | `/unsubscribe?t=…` | unsubscribe link from emails |
| GET, PUT | `/preferences` | preference centre |

## Partner webhooks

Partners receive `POST` requests with a JSON body (`event`, `data`, `sent_at`).
Webhook deliveries carry an `X-Tallowbrook-Signature` header: an HMAC-SHA256 of the raw body, hex-encoded.
Compare it with your own computation over the exact bytes received, before parsing.

Deliveries are retried up to eight times with exponential backoff, starting at two seconds.
A 4xx response other than 429 stops the retries.

## Receipt keys

Run `mix notify.gen.receipt_key` to create a new key pair, then follow the rotation runbook
in the ops wiki.
