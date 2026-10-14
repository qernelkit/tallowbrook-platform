# frozen_string_literal: true

# Tokens for carrier partners calling the admin API. We issue tokens to partners, and accept
# tokens partners sign themselves with the key they registered.
class PartnerTokens
  def issue(partner, scopes:)
    claims = {
      iss: PARTNER_TOKEN_ISSUER,
      sub: partner.code,
      scope: scopes.join(" "),
      exp: Time.now.to_i + PARTNER_TOKEN_TTL
    }
    JWT.encode(claims, issuer_key, PARTNER_TOKEN_ALG)
  end

  def check(partner, token)
    payload, = JWT.decode(token, OpenSSL::PKey.read(partner.verify_pem), true, algorithms: %w[ES256 ES384])
    payload["sub"] == partner.code ? payload : nil
  rescue JWT::DecodeError
    nil
  end

  private

  def issuer_key
    @issuer_key ||= OpenSSL::PKey.read(Rails.application.credentials.partner_token_pem)
  end
end
