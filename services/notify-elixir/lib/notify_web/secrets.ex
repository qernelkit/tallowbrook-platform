defmodule NotifyWeb.Secrets do
  @moduledoc "Per-purpose secrets derived from the endpoint's secret_key_base."

  @spec derive(String.t()) :: binary()
  def derive(salt), do: Plug.Crypto.KeyGenerator.generate(NotifyWeb.Endpoint.secret_key_base(), salt)
end
