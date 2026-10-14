# frozen_string_literal: true

# Keys for operator archives (incident evidence, exported mailboxes). Archives for the NAS use
# scrypt; archives handed to the external auditors use PBKDF2, the only option their tool has.
class ArchiveKeys
  SALT_BYTES = 16

  def self.new_salt
    SecureRandom.random_bytes(SALT_BYTES)
  end

  def for_auditors(phrase, salt)
    OpenSSL::KDF.pbkdf2_hmac(phrase, salt: salt,
                             iterations: ARCHIVE_PBKDF2_ITERATIONS, length: 32, hash: "sha256")
  end

  def for_nas(phrase, salt)
    OpenSSL::KDF.scrypt(phrase, salt: salt,
                        N: 2**15, r: 8, p: 1, length: 32)
  end

  def key_for(archive_kind, phrase, salt)
    raise ArgumentError, "archive phrase must be at least 16 characters" if phrase.to_s.length < 16

    case archive_kind
    when :auditors then for_auditors(phrase, salt)
    when :nas then for_nas(phrase, salt)
    else raise ArgumentError, "unknown archive kind #{archive_kind.inspect}"
    end
  end
end
