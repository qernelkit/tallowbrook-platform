# frozen_string_literal: true

# Authenticator codes for staff. Enrolments since the 2024 switch use SHA-256 secrets; older
# enrolments keep working until the staff member re-enrols.
class StaffMfa
  ISSUER = "Tallowbrook Admin"
  DRIFT_SECONDS = 15

  def initialize(staff)
    @staff = staff
  end

  def provisioning_uri
    totp.provisioning_uri
  end

  def verify(code)
    timestamp = totp.verify(code.to_s.delete(" "), drift_behind: DRIFT_SECONDS, after: @staff.otp_last_used_at&.to_i)
    return false unless timestamp

    @staff.update!(otp_last_used_at: Time.zone.at(timestamp))
    true
  end

  private

  # Authenticator apps show the account name; base64 keeps addresses with "+" readable in all of them.
  def totp
    label = Base64.strict_encode64(@staff.email)
    if @staff.otp_secret_v1.present?
      ROTP::TOTP.new(@staff.otp_secret_v1, name: label, issuer: ISSUER)
    else
      ROTP::TOTP.new(@staff.otp_secret, name: label, issuer: ISSUER, digest: "sha256")
    end
  end
end
