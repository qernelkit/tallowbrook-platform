# frozen_string_literal: true

class WebhooksController < ActionController::API
  def carrier
    carrier = Carrier.find_by(code: params[:carrier_code])
    return head :not_found unless carrier

    update = CarrierWebhooks.new.accept!(carrier, request)
    Shipment.where(tracking_number: update[:tracking_number]).update_all(status: update[:status], status_at: update[:at])
    head :accepted
  rescue CarrierWebhooks::Rejected, JSON::ParserError, KeyError => e
    Rails.logger.warn("carrier webhook from #{params[:carrier_code]} rejected: #{e.message}")
    head :bad_request
  end
end
