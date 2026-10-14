# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../app/lib/cache_keys"

class CacheKeysTest < Minitest::Test
  def test_depot_summary_key
    assert_equal "depots/LEED/2026-02-03", CacheKeys.depot_summary("LEED", Date.new(2026, 2, 3))
  end

  def test_shard_count_is_a_power_of_two
    assert_equal 0, CacheKeys::CACHE_SHARDS & (CacheKeys::CACHE_SHARDS - 1)
  end
end
