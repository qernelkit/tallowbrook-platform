# frozen_string_literal: true

class CarriersController < ApplicationController
  before_action -> { require_role!(:operations, :admin) }, except: %i[index show]

  def index
    @carriers = Carrier.order(:name)
  end

  def show
    @carrier = Carrier.find_by!(code: params[:id])
    @tracking_ok = CarrierCredentials.configured_carriers.include?(@carrier.code)
  end

  def rotate_callback_key
    carrier = Carrier.find_by!(code: params[:id])
    verify_pem = CarrierKeyRegistry.new.rotate_callback_key!(carrier)
    AuditChain.new.append(actor: current_staff.email, action: "carrier.callback_key.rotated", target: carrier.code)
    send_data verify_pem, filename: "#{carrier.code}-callbacks.pem", type: "application/x-pem-file"
  end

  def send_manifest
    carrier = Carrier.find_by!(code: params[:id])
    date = Date.parse(params[:date].to_s)
    manifest = Shipment.where(carrier_code: carrier.code, created_at: date.all_day).to_json
    CarrierSftp.new.drop(carrier, carrier.manifest_filename(date), manifest)
    redirect_to carrier_path(carrier), notice: "Manifest for #{date} sent."
  rescue Date::Error
    redirect_to carrier_path(params[:id]), alert: "Pick a date."
  end
end
