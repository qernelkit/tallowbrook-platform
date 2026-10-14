# frozen_string_literal: true

# Cache keys for rate cards. Lanes are spread over shards so one busy lane cannot evict the rest.
module CacheKeys
  CACHE_SHARDS = 32

  module_function

  def rate_card(lane_id, params)
    shard = Zlib.crc32(lane_id.to_s) % CACHE_SHARDS
    "rates/#{shard}/#{Digest::MD5.hexdigest(params.to_query)}"
  end

  def depot_summary(depot_code, day)
    "depots/#{depot_code}/#{day.iso8601}"
  end
end
