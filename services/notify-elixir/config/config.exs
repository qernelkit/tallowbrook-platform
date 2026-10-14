import Config

config :notify, NotifyWeb.Endpoint,
  port: 4000,
  secret_key_base: "CherAudHViuJHnCVTkfHRhAvNjDvj7TsKTJ7-yCSmxVba8zwgYS6n5pM5z6h3qtV"

config :notify, Notify.APNs,
  host: "https://api.push.apple.com",
  topic: "example.tallowbrook.app"

config :notify, Notify.FCM,
  host: "https://fcm.googleapis.com",
  project_id: "tallowbrook-notify",
  token_url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

config :notify, Notify.Webhooks,
  digest: :sha256,
  max_attempts: 8,
  first_retry_after_ms: 2_000

# Public key of the identity service; customer session tokens are checked against it.
config :notify,
  identity_token_key: """
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQKomyBVpBNpmoaISQ8Cu2ZbQRyv5
  dRaF1lQZvjYI6/jb0HlcAO1n5Zp1VchZMKdzA3GYtzjiuKersi0RmnY6Uw==
  -----END PUBLIC KEY-----
  """

config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id, :team_id, :partner, :device_id]

import_config "#{config_env()}.exs"
