# frozen_string_literal: true

class Export < ApplicationRecord
  serialize :filters, coder: JSON

  def csv
    rows = Shipment.filtered(filters).limit(100_000).pluck(:tracking_number, :carrier_code, :status, :delivered_at)
    CSV.generate do |out|
      out << %w[tracking_number carrier status delivered_at]
      rows.each { |row| out << row }
    end
  end
end
