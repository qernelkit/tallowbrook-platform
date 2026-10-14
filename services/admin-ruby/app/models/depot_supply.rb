# frozen_string_literal: true

# Consumables the depots order through the admin: labels, tape, pallets, winter supplies.
class DepotSupply < ApplicationRecord
  LABEL_ROLL_SKU = "LBL-100x150-500"
  PALLET_WRAP_SKU = "PLT-WRAP-23MU"
  ROAD_SALT_SKU = "WNT-SALT-25KG"

  WINTER_ONLY = [ROAD_SALT_SKU].freeze

  validates :sku, presence: true
  validates :quantity, numericality: { only_integer: true, greater_than: 0 }

  def seasonal?
    WINTER_ONLY.include?(sku)
  end

  def orderable_on?(date)
    !seasonal? || [11, 12, 1, 2, 3].include?(date.month)
  end
end
