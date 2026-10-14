# frozen_string_literal: true

class NewsletterSubscriber < ApplicationRecord
  validates :email, presence: true
  validates :frequency, inclusion: { in: %w[daily weekly monthly] }
end
