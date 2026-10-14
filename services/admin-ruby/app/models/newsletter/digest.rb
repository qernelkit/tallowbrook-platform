# frozen_string_literal: true

# The customer newsletter: a round-up of service news, depot openings and holiday cut-offs.
class Newsletter::Digest < ApplicationRecord
  FREQUENCIES = %w[daily weekly monthly].freeze

  validates :frequency, inclusion: { in: FREQUENCIES }
  validates :subject, presence: true, length: { maximum: 120 }

  scope :scheduled, -> { where(sent_at: nil).where.not(send_at: nil) }

  def due?(now = Time.current)
    sent_at.nil? && send_at.present? && send_at <= now
  end

  def deliver_digest!
    raise ArgumentError, "newsletter #{id} has no body" if body.blank?

    update!(sent_at: Time.current, recipient_count: subscriber_scope.count)
  end

  def subscriber_scope
    NewsletterSubscriber.where(frequency: frequency, unsubscribed_at: nil)
  end
end
