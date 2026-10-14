defmodule Notify.APNs.ProviderToken do
  @moduledoc """
  The provider authentication token APNs expects in every request. Apple refuses tokens
  older than an hour and throttles providers that refresh more than every 20 minutes,
  so one token is reused for 50 minutes.
  """
  use Agent
  require Logger

  @refresh_after_seconds 50 * 60

  def start_link(opts) do
    Agent.start_link(fn -> nil end, name: Keyword.get(opts, :name, __MODULE__))
  end

  @spec current(Agent.agent()) :: String.t()
  def current(agent \\ __MODULE__) do
    now = System.system_time(:second)

    Agent.get_and_update(agent, fn
      {token, issued_at} = state when now - issued_at < @refresh_after_seconds ->
        {token, state}

      _ ->
        token = build(Application.fetch_env!(:notify, Notify.APNs), now)
        {token, {token, now}}
    end)
  end

  @spec build(keyword(), integer()) :: String.t()
  def build(settings, issued_at) do
    team_id = Keyword.fetch!(settings, :team_id)
    key_id = Keyword.fetch!(settings, :key_id)
    claims = %{"iss" => team_id, "iat" => issued_at}
    header = %{"alg" => "ES256", "kid" => key_id}
    signing_input = b64(Jason.encode!(header)) <> "." <> b64(Jason.encode!(claims))
    der = :public_key.sign(signing_input, :sha256, signing_key(settings))
    Logger.info("APNs provider token refreshed", team_id: team_id)
    signing_input <> "." <> b64(raw_signature(der))
  end

  # The .p8 file Apple issues, read from APNS_KEY_PATH.
  defp signing_key(settings) do
    [entry] = settings |> Keyword.fetch!(:key_path) |> File.read!() |> :public_key.pem_decode()
    :public_key.pem_entry_decode(entry)
  end

  # JWS wants r ‖ s, not the DER sequence :public_key returns.
  defp raw_signature(der) do
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    <<r::unsigned-big-size(256), s::unsigned-big-size(256)>>
  end

  defp b64(data), do: Base.url_encode64(data, padding: false)
end
