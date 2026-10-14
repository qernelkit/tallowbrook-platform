defmodule Notify.APNs.Client do
  @moduledoc "Sends notifications to the customer iOS app through APNs (HTTP/2)."
  require Logger

  alias Notify.APNs.ProviderToken

  @type result :: :ok | {:error, :unregistered | :bad_token | {:retry, pos_integer()} | term()}

  @spec push(String.t(), map(), keyword()) :: result()
  def push(device_token, payload, opts \\ []) do
    settings = Application.fetch_env!(:notify, Notify.APNs)
    url = "#{Keyword.fetch!(settings, :host)}/3/device/#{device_token}"

    headers = [
      {"authorization", "bearer " <> ProviderToken.current()},
      {"apns-topic", Keyword.fetch!(settings, :topic)},
      {"apns-push-type", Keyword.get(opts, :push_type, "alert")},
      {"apns-priority", if(Keyword.get(opts, :urgent, true), do: "10", else: "5")},
      {"apns-collapse-id", Keyword.get(opts, :collapse_id, "")}
    ]

    request = Finch.build(:post, url, Enum.reject(headers, fn {_, v} -> v == "" end), Jason.encode!(payload))

    case Finch.request(request, Notify.Push.Finch, receive_timeout: 10_000) do
      {:ok, %Finch.Response{status: 200}} ->
        :ok

      {:ok, %Finch.Response{status: 410}} ->
        {:error, :unregistered}

      {:ok, %Finch.Response{status: 400, body: body}} ->
        Logger.warning("APNs rejected a notification: #{body}")
        {:error, :bad_token}

      {:ok, %Finch.Response{status: status, headers: response_headers}} when status in [429, 500, 503] ->
        {:error, {:retry, retry_after(response_headers)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "An alert for a parcel status change, as the iOS app's notification extension expects it."
  @spec parcel_alert(String.t(), String.t(), String.t()) :: map()
  def parcel_alert(tracking_number, title, body) do
    %{
      "aps" => %{"alert" => %{"title" => title, "body" => body}, "sound" => "default", "thread-id" => tracking_number},
      "tracking_number" => tracking_number
    }
  end

  defp retry_after(headers) do
    case List.keyfind(headers, "retry-after", 0) do
      {_, value} -> String.to_integer(value)
      nil -> 30
    end
  end
end
