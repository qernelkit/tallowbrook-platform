defmodule Notify.Webhooks.Client do
  @moduledoc "Delivers webhooks to partners, retrying with exponential backoff."
  require Logger

  @type partner :: %{id: String.t(), url: String.t(), secret: String.t()}

  defmodule Pool do
    @moduledoc false

    def child_spec(_opts) do
      settings = Application.fetch_env!(:notify, Notify.Webhooks)

      Finch.child_spec(
        name: Notify.Webhooks.Finch,
        pools: %{
          default: [
            size: 10,
            conn_opts: [
              transport_opts: [
                versions: Keyword.fetch!(settings, :tls_versions),
                cacerts: :public_key.cacerts_get()
              ]
            ]
          ]
        }
      )
    end
  end

  @spec deliver(partner(), String.t(), map(), module()) :: :ok | {:error, term()}
  def deliver(partner, event, payload, signer \\ Notify.Webhooks.Signer) do
    settings = Application.fetch_env!(:notify, Notify.Webhooks)
    body = Jason.encode!(%{"event" => event, "data" => payload, "sent_at" => DateTime.utc_now()})

    headers = [
      {"content-type", "application/json"},
      {"x-tallowbrook-event", event},
      {"x-tallowbrook-signature", signer.sign(body, partner.secret)}
    ]

    attempt(
      partner,
      headers,
      body,
      1,
      Keyword.fetch!(settings, :max_attempts),
      Keyword.fetch!(settings, :first_retry_after_ms)
    )
  end

  defp attempt(partner, headers, body, n, max, delay_ms) do
    request = Finch.build(:post, partner.url, headers, body)

    case Finch.request(request, Notify.Webhooks.Finch, receive_timeout: 15_000) do
      {:ok, %Finch.Response{status: status}} when status in 200..299 ->
        :ok

      {:ok, %Finch.Response{status: status}} when status in 400..499 and status != 429 ->
        Logger.warning("Partner rejected webhook with #{status}", partner: partner.id)
        {:error, {:rejected, status}}

      other when n < max ->
        Logger.info("Webhook attempt #{n} failed: #{inspect(other)}", partner: partner.id)
        Process.sleep(delay_ms)
        attempt(partner, headers, body, n + 1, max, delay_ms * 2)

      other ->
        {:error, {:gave_up, other}}
    end
  end
end
