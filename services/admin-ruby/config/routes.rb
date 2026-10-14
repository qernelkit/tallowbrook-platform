# frozen_string_literal: true

Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  resources :staff, only: %i[index show] do
    member do
      post :reset_mfa
    end
  end

  resources :exports, only: %i[index create show]
  resources :carriers, only: %i[index show] do
    member do
      post :rotate_callback_key
      post :send_manifest
    end
  end
  resources :devices, only: %i[index create]
  resources :notes, only: %i[create show]
  resources :coupons, only: %i[create]

  post "webhooks/carriers/:carrier_code", to: "webhooks#carrier", as: :carrier_webhook
end
