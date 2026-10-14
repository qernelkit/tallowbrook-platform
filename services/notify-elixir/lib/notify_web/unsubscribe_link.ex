defmodule NotifyWeb.UnsubscribeLink do
  @moduledoc """
  One-click unsubscribe links in notification emails (RFC 8058). The link carries the
  subscriber and topic, signed so it cannot be edited to unsubscribe someone else.
  """
  alias NotifyWeb.Secrets

  @base "https://notify.tallowbrook.example/unsubscribe"

  @spec url(String.t(), String.t()) :: String.t()
  def url(subscriber_id, topic) do
    token =
      Plug.Crypto.MessageVerifier.sign(
        :erlang.term_to_binary({subscriber_id, topic}),
        Secrets.derive("unsubscribe link")
      )

    @base <> "?t=" <> token
  end

  @spec parse(String.t()) :: {:ok, {String.t(), String.t()}} | :error
  def parse(token) do
    case Plug.Crypto.MessageVerifier.verify(token, Secrets.derive("unsubscribe link")) do
      {:ok, binary} -> {:ok, Plug.Crypto.non_executable_binary_to_term(binary, [:safe])}
      :error -> :error
    end
  end
end
