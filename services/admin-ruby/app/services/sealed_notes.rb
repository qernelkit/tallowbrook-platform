# frozen_string_literal: true

# Staff-only case notes are sealed before they reach the database; only the admin can open them.
class SealedNotes
  def seal(note, plain)
    nonce = RbNaCl::Random.random_bytes(box.nonce_bytes)
    note.update!(sealed_body: Base64.strict_encode64(nonce + box.encrypt(nonce, plain)), sealed_at: Time.current)
    Rails.logger.info("Sealed note #{note.id} with the current encryption key")
  end

  private def box = (@box ||= RbNaCl::SecretBox.new(key))

  def open(note)
    raw = Base64.strict_decode64(note.sealed_body)
    box.decrypt(raw.byteslice(0, box.nonce_bytes), raw.byteslice(box.nonce_bytes..))
  end

  private

  def key
    hex = Rails.application.credentials.notes_key or raise KeyError, "credentials have no notes_key"
    [hex].pack("H*")
  end
end
