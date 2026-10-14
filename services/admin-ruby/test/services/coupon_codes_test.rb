# frozen_string_literal: true

require_relative "../test_helper"
require "securerandom"
require_relative "../../app/services/coupon_codes"

class CouponCodesTest < Minitest::Test
  def test_printed_codes_read_back
    CouponCodes.generate(50).each do |code|
      assert_equal code, CouponCodes.from_printed(CouponCodes.printable(code))
    end
  end

  def test_reader_ignores_dashes_and_case
    code = CouponCodes.generate(1).first
    printed = CouponCodes.printable(code).downcase.scan(/.{4}/).join("-")

    assert_equal code, CouponCodes.from_printed(printed)
  end

  def test_generated_codes_use_the_alphabet
    assert(CouponCodes.generate(20).all? { |c| c.match?(/\A[A-HJ-NP-Z2-9]{8}\z/) })
  end
end
