# frozen_string_literal: true

# Keys exchanged with carrier partners at onboarding.
class CarrierKeyRegistry
  # The carrier verifies our status callbacks with the public half of this pair.
  def rotate_callback_key!(carrier)
    key = OpenSSL::PKey::RSA.new(2048)
    carrier.update!(callback_key_pem: key.private_to_pem, callback_verify_pem: key.public_to_pem, callback_key_rotated_at: Time.current)
    key.public_to_pem
  end

  # API secrets for the carrier's sandbox and production accounts are sent to them wrapped with the
  # key they registered with us, so the secret is never readable in the onboarding email.
  def wrap_api_secret(carrier, api_secret)
    wrapping = OpenSSL::PKey.read(carrier.wrapping_pem)
    wrapped = wrapping.encrypt(api_secret,
                               "rsa_padding_mode" => "oaep",
                               "rsa_oaep_md" => "sha256")
    Base64.strict_encode64(wrapped)
  end
end
