# frozen_string_literal: true

# Signs the audit bundles we hand to the external auditors (pilot, agreed with them for 2026).
class AuditBundleSigner
  def initialize(vault)
    @vault = vault
  end

  # Run once when the pilot starts; the auditors get the public half by email.
  def provision!
    key = OpenSSL::PKey.generate_key("ML-DSA-65")
    @vault.store(key.private_to_pem)
    key.public_to_pem
  end

  def sign(bundle)
    key = OpenSSL::PKey.read(@vault.key_pem)
    Base64.strict_encode64(key.sign(nil, bundle))
  end
end
