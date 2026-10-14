defmodule Notify.Push.Pool do
  @moduledoc """
  Finch pools for APNs and FCM. Both are long-lived HTTP/2 connections to endpoints we
  do not control, so the client's TLS offer is pinned down here.
  """

  def child_spec(_opts) do
    Finch.child_spec(name: Notify.Push.Finch, pools: pools())
  end

  def pools do
    apns = Application.fetch_env!(:notify, Notify.APNs) |> Keyword.fetch!(:host)
    fcm = Application.fetch_env!(:notify, Notify.FCM) |> Keyword.fetch!(:host)

    %{
      apns => [protocols: [:http2], count: 2, conn_opts: [transport_opts: transport_opts()]],
      fcm => [protocols: [:http2], count: 2, conn_opts: [transport_opts: transport_opts()]],
      :default => [size: 4]
    }
  end

  @spec transport_opts() :: keyword()
  def transport_opts do
    [
      cacerts: :public_key.cacerts_get(),
      ciphers: Enum.map([~c"TLS_AES_256_GCM_SHA384", ~c"TLS_CHACHA20_POLY1305_SHA256"], &:ssl.str_to_suite/1),
      supported_groups: [:x25519mlkem768, :x25519, :secp256r1],
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]
  end
end
