# frozen_string_literal: true

# Parcel status webhooks from carriers ("picked up", "out for delivery", "delivered").
class CarrierWebhooks
  class Rejected < StandardError; end

  STATUSES = %w[picked_up in_transit out_for_delivery delivered failed_attempt returned].freeze

  def accept!(carrier, request)
    expected = OpenSSL::HMAC.hexdigest("SHA1", carrier.webhook_secret, request.raw_post)
    given = request.headers["X-Carrier-Signature"].to_s.downcase
    raise Rejected, "bad signature from #{carrier.code}" unless ActiveSupport::SecurityUtils.secure_compare(expected, given)

    event = JSON.parse(request.raw_post)
    raise Rejected, "unknown status #{event['status']}" unless STATUSES.include?(event["status"])

    { tracking_number: event.fetch("tracking_number"), status: event["status"], at: Time.zone.parse(event.fetch("occurred_at")) }
  end
end
