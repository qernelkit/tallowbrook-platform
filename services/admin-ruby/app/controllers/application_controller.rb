# frozen_string_literal: true

class ApplicationController < ActionController::Base
  before_action :require_staff
  before_action :require_second_factor

  helper_method :current_staff

  private

  def current_staff
    @current_staff ||= StaffUser.active.find_by(id: session[:staff_id])
  end

  def require_staff
    redirect_to "/auth/sso" unless current_staff
  end

  def require_second_factor
    return if session[:mfa_verified_at].present? && session[:mfa_verified_at] > 12.hours.ago.to_i

    redirect_to "/mfa"
  end

  def require_role!(*roles)
    head :forbidden unless roles.map(&:to_s).include?(current_staff.role)
  end
end
