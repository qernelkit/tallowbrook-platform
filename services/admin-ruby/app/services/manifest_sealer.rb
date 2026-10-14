# frozen_string_literal: true

# Seals the day's delivery manifest for a depot scanner, so only that device can read the
# addresses on it. The scanner registered its key at enrolment.
class ManifestSealer
  INFO = "manifest-v1"

  def seal(device, manifest_json)
    ephemeral = OpenSSL::PKey::EC.generate("prime256v1")
    device_key = OpenSSL::PKey.read(device.sealing_pem)
    shared = ephemeral.derive(device_key)
    key = OpenSSL::KDF.hkdf(shared,
                            salt: device.serial, info: INFO, length: 32,
                            hash: "SHA256")

    gcm = OpenSSL::Cipher.new("aes-256-gcm").encrypt
    gcm.key = key
    iv = gcm.random_iv
    gcm.auth_data = device.serial
    body = gcm.update(manifest_json) + gcm.final

    {
      ephemeral: ephemeral.public_to_pem,
      iv: Base64.strict_encode64(iv),
      tag: Base64.strict_encode64(gcm.auth_tag),
      body: Base64.strict_encode64(body)
    }
  end
end
