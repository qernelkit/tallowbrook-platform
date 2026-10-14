defmodule NotifyWeb.Endpoint do
  @moduledoc """
  The HTTP entry point. Phoenix-style, without Phoenix: settings live under
  `config :notify, NotifyWeb.Endpoint`, including `secret_key_base`.
  """
  use Plug.Builder

  plug(Plug.RequestId)
  plug(Plug.Logger, log: :debug)
  plug(Plug.Head)
  plug(Plug.Parsers, parsers: [:json, :urlencoded], json_decoder: Jason, pass: ["application/json"])
  plug(NotifyWeb.Router)

  @spec config(atom()) :: term()
  def config(key), do: Application.fetch_env!(:notify, __MODULE__) |> Keyword.get(key)

  @spec port() :: :inet.port_number()
  def port, do: config(:port)

  @spec secret_key_base() :: String.t()
  def secret_key_base, do: config(:secret_key_base)
end
