defmodule Notify.Test.FixedSigner do
  @moduledoc "Stands in for Notify.Webhooks.Signer so tests need no partner secret."
  @behaviour Notify.Webhooks.Signer

  @impl true
  def sign(_body, _secret), do: "fixed"
end
