# frozen_string_literal: true

Rails.application.configure do
  config.enable_reloading = false
  config.eager_load = true
  config.consider_all_requests_local = false

  config.action_controller.perform_caching = true
  config.cache_store = :memory_store, { size: 64.megabytes }

  config.force_ssl = true
  config.assume_ssl = true

  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info")
  config.log_tags = [:request_id]

  config.action_mailer.default_url_options = { host: "admin.tallowbrook.example", protocol: "https" }
  config.active_record.dump_schema_after_migration = false
  config.hosts << "admin.tallowbrook.example"
end
