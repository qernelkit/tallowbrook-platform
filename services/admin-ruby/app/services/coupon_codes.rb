# frozen_string_literal: true

# Coupon codes printed on parcel inserts. The printed form is shifted so that a code cannot be
# guessed from the sequence on neighbouring inserts.
class CouponCodes
  ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
  SHIFT = 11

  def self.generate(count)
    Array.new(count) { Array.new(8) { ALPHABET[SecureRandom.random_number(ALPHABET.size)] }.join }
  end

  def self.printable(code) = shift(code.upcase, SHIFT)

  def self.from_printed(text) = shift(text.upcase.delete("- "), -SHIFT)

  def self.shift(text, by)
    text.tr(ALPHABET, ALPHABET.chars.rotate(by).join)
  end
  private_class_method :shift
end
