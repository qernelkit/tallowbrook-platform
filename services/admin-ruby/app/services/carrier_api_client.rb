# frozen_string_literal: true

require "net/http"

# Thin HTTPS client for the carriers' tracking APIs.
class CarrierApiClient
  class Error < StandardError; end

  def initialize(carrier, token: CarrierCredentials.token_for(carrier.code))
    @carrier = carrier
    @token = token
  end

  def tracking(tracking_number)
    get("/v1/tracking/#{ERB::Util.url_encode(tracking_number)}")
  end

  private

  def get(path)
    uri = URI.join(@carrier.api_base, path)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.min_version = :TLS1_2
    http.open_timeout = 5
    http.read_timeout = 15

    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{@token}"
    request["Accept"] = "application/json"
    response = http.request(request)
    raise Error, "#{@carrier.code} answered #{response.code}" unless response.is_a?(Net::HTTPSuccess)

    JSON.parse(response.body)
  end
end
