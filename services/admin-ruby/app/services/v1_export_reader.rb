# frozen_string_literal: true

require "csv"

# Reads CSV exports written by the old admin, for staff who still have them on shared drives.
# File layout: 16-byte IV, then the CSV.
class V1ExportReader
  class Unreadable < StandardError; end

  def initialize(key_hex: Rails.application.credentials.v1_export_key)
    raise Unreadable, "credentials have no v1_export_key" if key_hex.blank?

    @key = [key_hex].pack("H*")
  end

  def rows(blob)
    raise Unreadable, "file is too short" if blob.bytesize <= 16

    cbc = OpenSSL::Cipher.new(EXPORT_CIPHER).decrypt
    cbc.key = @key
    cbc.iv = blob.byteslice(0, 16)
    csv = cbc.update(blob.byteslice(16..)) + cbc.final
    CSV.parse(csv, headers: true).map(&:to_h)
  rescue OpenSSL::Cipher::CipherError
    raise Unreadable, "wrong key or damaged file"
  end
end
