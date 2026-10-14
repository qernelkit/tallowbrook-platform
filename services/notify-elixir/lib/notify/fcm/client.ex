defmodule Notify.FCM.Client do
  @moduledoc "Sends notifications to the scanner handhelds through the FCM HTTP v1 API."
  require Logger

  alias Notify.FCM.AccessToken

  @spec push(String.t(), map()) :: :ok | {:error, :unregistered | term()}
  def push(registration_token, data) do
    settings = Application.fetch_env!(:notify, Notify.FCM)
    url = "#{Keyword.fetch!(settings, :host)}/v1/projects/#{Keyword.fetch!(settings, :project_id)}/messages:send"

    body =
      Jason.encode!(%{
        "message" => %{
          "token" => registration_token,
          "data" => Map.new(data, fn {k, v} -> {to_string(k), to_string(v)} end),
          "android" => %{"priority" => "high", "ttl" => "3600s"}
        }
      })

    headers = [{"authorization", "Bearer " <> AccessToken.current()}, {"content-type", "application/json"}]

    case Finch.request(Finch.build(:post, url, headers, body), Notify.Push.Finch) do
      {:ok, %Finch.Response{status: 200}} ->
        :ok

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :unregistered}

      {:ok, %Finch.Response{status: status, body: resp}} ->
        Logger.warning("FCM returned #{status}: #{resp}")
        {:error, {:status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end

defmodule Notify.FCM.AccessToken do
  @moduledoc """
  OAuth access token for FCM. The service runs with a workload identity, so the token
  comes from the metadata server; no service-account key is stored anywhere.
  """
  use Agent

  def start_link(_opts), do: Agent.start_link(fn -> nil end, name: __MODULE__)

  @spec current() :: String.t()
  def current do
    now = System.monotonic_time(:second)

    Agent.get_and_update(__MODULE__, fn
      {token, expires_at} = state when expires_at - now > 60 -> {token, state}
      _ -> fetch(now)
    end)
  end

  defp fetch(now) do
    url = Application.fetch_env!(:notify, Notify.FCM) |> Keyword.fetch!(:token_url)
    request = Finch.build(:get, url, [{"metadata-flavor", "Google"}])
    {:ok, %Finch.Response{status: 200, body: body}} = Finch.request(request, Notify.Push.Finch)
    %{"access_token" => token, "expires_in" => expires_in} = Jason.decode!(body)
    {token, {token, now + expires_in}}
  end
end
