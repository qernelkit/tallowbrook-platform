# frozen_string_literal: true

Rails.application.config.filter_parameters += %i[
  token otp code webhook_secret api_secret phone delivery_note
]
