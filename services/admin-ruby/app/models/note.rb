# frozen_string_literal: true

# Staff-only notes on a customer case (complaints, fraud flags). The body is sealed by SealedNotes.
class Note < ApplicationRecord
  belongs_to :author, class_name: "StaffUser"

  validates :case_reference, presence: true, format: { with: /\ACASE-\d{6}\z/ }

  def sealed?
    sealed_body.present?
  end
end
