# frozen_string_literal: true

# Staff upload proof-of-delivery photos and claim documents; the same file is often attached to
# several cases. Uploads are stored once per content hash.
class UploadFingerprint
  def self.of(io)
    io.rewind
    Digest::SHA256.hexdigest(io.read)
  ensure
    io.rewind
  end

  def self.storage_path(content_hash, original_filename)
    ext = File.extname(original_filename.to_s).downcase.presence || ".bin"
    File.join("uploads", content_hash[0, 2], content_hash[2, 2], "#{content_hash}#{ext}")
  end
end
