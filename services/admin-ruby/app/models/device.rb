# frozen_string_literal: true

# A handheld scanner at a depot.
class Device < ApplicationRecord
  validates :serial, presence: true, uniqueness: true
  validates :depot_code, presence: true, length: { is: 4 }

  scope :at_depot, ->(code) { where(depot_code: code) }

  def label
    "#{depot_code}/#{serial}"
  end
end
