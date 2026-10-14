import Config

config :notify, NotifyWeb.Endpoint, port: 4042, server: false

config :notify, Notify.Webhooks, max_attempts: 1, first_retry_after_ms: 0

config :notify, start_pools: false

config :logger, level: :warning
