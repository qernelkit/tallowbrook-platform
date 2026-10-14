# frozen_string_literal: true

Rails.application.configure do
  config.enable_reloading = false
  config.eager_load = false
  config.consider_all_requests_local = true
  config.cache_store = :null_store
  config.action_controller.allow_forgery_protection = false
  config.action_mailer.delivery_method = :test
end
