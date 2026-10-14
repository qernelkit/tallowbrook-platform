# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../app/lib/lane_rate_hash"

class LaneRateHashTest < Minitest::Test
  def setup
    LaneRateHash.clear!
  end

  def test_loads_each_lane_once
    calls = 0
    loader = ->(o, d) { calls += 1; { origin: o, destination: d } }

    3.times { LaneRateHash.fetch(10, 20, loader: loader) }

    assert_equal 1, calls
    assert_equal 1, LaneRateHash.size
  end

  def test_direction_matters
    LaneRateHash.fetch(10, 20, loader: ->(o, d) { [o, d] })
    LaneRateHash.fetch(20, 10, loader: ->(o, d) { [o, d] })

    assert_equal 2, LaneRateHash.size
  end
end
