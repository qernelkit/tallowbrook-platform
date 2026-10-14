# frozen_string_literal: true

class ExportsController < ApplicationController
  before_action -> { require_role!(:finance, :admin) }

  def index
    @exports = Export.where(created_by: current_staff.id).order(created_at: :desc).limit(50)
  end

  def create
    filters = params.require(:filters).permit(:from, :to, :carrier, :depot).to_h
    export = Export.create!(created_by: current_staff.id, filters: filters, cache_key: SignedExportLinks.cache_key(filters))
    redirect_to export_path(export, token: SignedExportLinks.token_for(export, current_staff))
  end

  def show
    export_id, staff_id = SignedExportLinks.resolve(params[:token].to_s)
    return head :gone unless export_id && export_id.to_s == params[:id] && staff_id == current_staff.id

    export = Export.find(export_id)
    send_data export.csv, filename: "export-#{export.id}.csv", type: "text/csv"
  end
end
