# frozen_string_literal: true

# In-memory lane rate table: the quoting screen asks for the same few hundred lanes all day.
class LaneRateHash
  RATES = {} # rubocop:disable Style/MutableConstant

  def self.fetch(origin_id, destination_id, loader: method(:load_rate))
    RATES[[origin_id, destination_id].hash] ||= loader.call(origin_id, destination_id)
  end

  def self.clear!
    RATES.clear
  end

  def self.size
    RATES.size
  end

  def self.load_rate(origin_id, destination_id)
    { origin: origin_id, destination: destination_id, per_kg_cents: 0, loaded_at: Time.now.utc }
  end
end
