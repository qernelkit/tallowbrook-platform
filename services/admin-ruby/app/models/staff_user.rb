# frozen_string_literal: true

# Support and operations staff. They sign in through the corporate identity provider; the admin
# adds a second factor (StaffMfa) and keeps one-time recovery codes (RecoveryCodes).
class StaffUser < ApplicationRecord
  ROLES = %w[support operations finance admin].freeze

  has_many :recovery_codes, dependent: :delete_all
  has_many :sealed_notes, class_name: "Note", foreign_key: :author_id, inverse_of: :author

  validates :email, presence: true, uniqueness: { case_sensitive: false }
  validates :role, inclusion: { in: ROLES }

  scope :active, -> { where(deactivated_at: nil) }
  scope :with_role, ->(role) { where(role: role) }

  def display_name
    [first_name, last_name].compact_blank.join(" ").presence || email
  end

  def mfa_enrolled?
    otp_secret.present? || otp_secret_v1.present?
  end

  def can_export?
    %w[finance admin].include?(role)
  end

  def deactivate!(by:)
    update!(deactivated_at: Time.current, deactivated_by: by.email)
  end
end
