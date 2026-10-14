defmodule Notify.Webhooks.Signer do
  @moduledoc """
  Signs webhook bodies for partner systems. Partners check the `X-Tallowbrook-Signature`
  header against the shared secret they were issued.
  """

  @callback sign(binary(), String.t()) :: String.t()

  @digest Application.compile_env!(:notify, [Notify.Webhooks, :digest])

  @spec sign(binary(), String.t()) :: String.t()
  def sign(body, secret) do
    mac = :crypto.mac(:hmac, @digest, secret, body)
    Base.encode16(mac, case: :lower)
  end
end
