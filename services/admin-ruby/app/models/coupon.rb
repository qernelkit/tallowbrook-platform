# frozen_string_literal: true

class Coupon < ApplicationRecord
  validates :code, presence: true, uniqueness: true

  def redeemed?
    redeemed_at.present?
  end
end
