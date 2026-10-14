# frozen_string_literal: true

# Seals PII columns (phone numbers, delivery notes) before they are stored.
class PiiCipher
  class << self
    def seal(value)
      return nil if value.nil?

      encryptor.encrypt_and_sign(value)
    end

    def unseal(token)
      return nil if token.nil?

      encryptor.decrypt_and_verify(token)
    end

    private

    def encryptor
      @encryptor ||= ActiveSupport::MessageEncryptor.new(key, cipher: Rails.configuration.x.pii.cipher)
    end

    def key
      hex = Rails.application.credentials.pii_key or raise KeyError, "credentials have no pii_key"
      [hex].pack("H*")
    end
  end
end
