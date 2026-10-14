# frozen_string_literal: true

# Short-lived tokens for calls from the admin to internal services (billing, identity).
class InternalTokens
  TTL = 60

  def self.for(service, staff)
    claims = { aud: service, sub: "staff:#{staff.id}", role: staff.role, exp: Time.now.to_i + TTL }
    JWT.encode(claims, Rails.application.credentials.internal_token_secret)
  end
end
