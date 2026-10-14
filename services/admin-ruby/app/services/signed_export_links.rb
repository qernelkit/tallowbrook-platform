# frozen_string_literal: true

# Download links for CSV exports, valid for EXPORT_LINK_TTL. The link carries the export id and
# the staff member it was made for.
class SignedExportLinks
  def self.verifier
    @verifier ||= ActiveSupport::MessageVerifier.new(Rails.application.secret_key_base)
  end

  def self.cache_key(filters) = Base64.urlsafe_encode64(filters.to_json)

  def self.token_for(export, staff)
    verifier.generate({ "export_id" => export.id, "staff_id" => staff.id }, expires_in: EXPORT_LINK_TTL, purpose: :export_download)
  end

  def self.resolve(token)
    data = verifier.verified(token, purpose: :export_download)
    data && [data["export_id"], data["staff_id"]]
  end
end
