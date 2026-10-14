# frozen_string_literal: true

# Depots pull the current price list every morning; the scanner app refuses an unsigned list.
class PriceListSigner
  def initialize(seed_hex: Rails.application.credentials.price_list_seed)
    raise KeyError, "credentials have no price_list_seed" if seed_hex.blank?

    seed = [seed_hex].pack("H*")
    @signer = RbNaCl::Signatures::Ed25519::SigningKey.new(seed)
  end

  def sign(price_list_json)
    {
      body: price_list_json,
      signature: Base64.strict_encode64(@signer.sign(price_list_json)),
      key_id: key_id
    }
  end

  def key_id
    @signer.verify_key.to_bytes.unpack1("H*")[0, 16]
  end
end
