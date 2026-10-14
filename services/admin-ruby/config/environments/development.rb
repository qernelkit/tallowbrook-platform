# frozen_string_literal: true

Rails.application.configure do
  config.enable_reloading = true
  config.eager_load = false
  config.consider_all_requests_local = true
  config.server_timing = true

  config.action_controller.perform_caching = false
  config.cache_store = :memory_store

  config.action_mailer.raise_delivery_errors = false
  config.action_mailer.default_url_options = { host: "localhost", port: 3000 }

  config.active_record.migration_error = :page_load
  config.active_record.verbose_query_logs = true

  # Development only: a fixed key so signed export links survive server restarts.
  config.secret_key_base = ENV.fetch("SECRET_KEY_BASE", "85d20ac83a81d7cad06bd2eade3cd0e13a59d609081831bd6ea5222b7fce3a8189b4622792c690de894a9c0c91be37c3219bb8a7e60749c094829df9e6705990")
end
