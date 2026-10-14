import Config

# Partner endpoints: several partners still terminate on TLS 1.2.
config :notify, Notify.Webhooks, tls_versions: [:"tlsv1.3", :"tlsv1.2"]

if config_env() == :prod do
  config :notify, NotifyWeb.Endpoint,
    port: String.to_integer(System.get_env("PORT", "4000")),
    secret_key_base: System.fetch_env!("SECRET_KEY_BASE")

  config :notify, Notify.APNs,
    key_path: System.fetch_env!("APNS_KEY_PATH"),
    key_id: System.fetch_env!("APNS_KEY_ID"),
    team_id: System.fetch_env!("APNS_TEAM_ID")

  config :notify, Notify.Receipts, key_path: System.fetch_env!("RECEIPT_KEY_PATH")

  config :notify, Notify.Store.PayloadVault, key_path: System.fetch_env!("PAYLOAD_VAULT_KEY_PATH")

  config :logger, level: String.to_existing_atom(System.get_env("LOG_LEVEL", "info"))
end
