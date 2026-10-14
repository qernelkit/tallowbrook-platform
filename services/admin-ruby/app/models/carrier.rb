# frozen_string_literal: true

# A carrier partner: API base URL, SFTP drop, webhook secret and the keys exchanged at onboarding.
class Carrier < ApplicationRecord
  validates :code, presence: true, uniqueness: true, format: { with: /\A[a-z0-9-]+\z/ }
  validates :api_base, presence: true

  scope :with_sftp_drop, -> { where.not(sftp_host: nil) }

  def to_param
    code
  end

  def manifest_filename(date)
    "#{code}_manifest_#{date.strftime('%Y%m%d')}.json"
  end
end
