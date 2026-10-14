# frozen_string_literal: true

class Shipment < ApplicationRecord
  def self.filtered(filters)
    scope = all
    scope = scope.where(created_at: filters["from"]..) if filters["from"].present?
    scope = scope.where(created_at: ..filters["to"]) if filters["to"].present?
    scope = scope.where(carrier_code: filters["carrier"]) if filters["carrier"].present?
    scope = scope.where(depot_code: filters["depot"]) if filters["depot"].present?
    scope
  end
end
