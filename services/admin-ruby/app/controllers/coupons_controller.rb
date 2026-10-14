# frozen_string_literal: true

class CouponsController < ApplicationController
  MAX_BATCH = 5_000

  def create
    count = params.require(:count).to_i
    return head :unprocessable_entity unless count.between?(1, MAX_BATCH)

    codes = CouponCodes.generate(count)
    Coupon.insert_all(codes.map { |code| { code: code, campaign: params[:campaign], created_at: Time.current, updated_at: Time.current } })
    csv = codes.map { |code| CouponCodes.printable(code) }.join("\n")
    send_data csv, filename: "coupons-#{params[:campaign]}.txt"
  end
end
