import Config

config :notify, NotifyWeb.Endpoint, port: 4040

config :notify, Notify.Webhooks, max_attempts: 2

config :logger, level: :debug
