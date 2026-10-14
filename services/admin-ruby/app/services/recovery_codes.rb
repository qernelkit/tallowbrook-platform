# frozen_string_literal: true

# One-time recovery codes for staff who lose their authenticator. The identity service checks
# them at sign-in; the admin only issues them.
class RecoveryCodes
  COUNT = 10
  ALPHABET = ("a".."z").to_a - %w[i l o] + ("2".."9").to_a

  def initialize(staff)
    @staff = staff
  end

  # Returns the plain codes once, for the staff member to print.
  def issue!
    codes = Array.new(COUNT) { Array.new(10) { ALPHABET.sample(random: SecureRandom) }.join.scan(/.{5}/).join("-") }
    RecoveryCode.transaction do
      @staff.recovery_codes.delete_all
      codes.each { |code| @staff.recovery_codes.create!(code_hash: hash_code(code)) }
    end
    codes
  end

  def remaining
    @staff.recovery_codes.unused.count
  end

  private

  def hash_code(code)
    BCrypt::Password.create(code, cost: 12).to_s
  end
end
