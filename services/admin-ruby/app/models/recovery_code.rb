# frozen_string_literal: true

class RecoveryCode < ApplicationRecord
  belongs_to :staff_user

  scope :unused, -> { where(used_at: nil) }

  def use!
    update!(used_at: Time.current)
  end
end
