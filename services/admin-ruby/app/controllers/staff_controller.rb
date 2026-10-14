# frozen_string_literal: true

class StaffController < ApplicationController
  before_action -> { require_role!(:admin) }, only: :reset_mfa

  def index
    @staff = StaffUser.active.order(:last_name, :first_name)
    @staff = @staff.with_role(params[:role]) if StaffUser::ROLES.include?(params[:role])
  end

  def show
    @member = StaffUser.find(params[:id])
    @recovery_codes_left = RecoveryCodes.new(@member).remaining
  end

  def reset_mfa
    member = StaffUser.find(params[:id])
    member.update!(otp_secret: nil, otp_secret_v1: nil, otp_last_used_at: nil)
    AuditChain.new.append(actor: current_staff.email, action: "mfa.reset", target: member.email)
    redirect_to staff_path(member), notice: "#{member.display_name} will enrol again at next sign-in."
  end
end
