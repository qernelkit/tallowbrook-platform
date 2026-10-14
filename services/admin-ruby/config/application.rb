# frozen_string_literal: true

require_relative "boot"

require "rails"
require "active_model/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_mailer/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)

module AdminConsole
  class Application < Rails::Application
    config.load_defaults 8.1

    config.time_zone = "UTC"
    config.active_record.default_timezone = :utc
    config.generators.system_tests = nil

    # PII columns (phone numbers, delivery notes) are sealed by PiiCipher before they are stored.
    config.x.pii.cipher = "aes-256-gcm"

    config.x.support_inbox = "support@tallowbrook.example"
    config.x.export_retention_days = 30
  end
end
