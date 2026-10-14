# frozen_string_literal: true

# API tokens for the carriers' tracking APIs, kept in an encrypted file next to the credentials.
class CarrierCredentials
  class Missing < StandardError; end

  def self.store
    @store ||= Rails.application.encrypted("config/carrier_tokens.yml.enc")
  end

  def self.token_for(carrier_code)
    store.config.dig(carrier_code.to_sym, :api_token) or raise Missing, "no API token for carrier #{carrier_code}"
  end

  def self.configured_carriers
    store.config.keys.map(&:to_s).sort
  end
end
