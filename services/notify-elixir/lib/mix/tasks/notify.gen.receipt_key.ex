defmodule Mix.Tasks.Notify.Gen.ReceiptKey do
  @shortdoc "Generates a receipt key pair"
  @moduledoc """
  Generates the key pair for delivery receipts.

      mix notify.gen.receipt_key

  Put the private half in the secrets store (RECEIPT_KEY_PATH points at it) and publish
  the public half on the partner portal.
  """
  use Mix.Task

  @impl Mix.Task
  def run(_args) do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    Mix.shell().info("private (secrets store): " <> Base.encode64(private))
    Mix.shell().info("public (partner portal): " <> Base.encode64(public))
  end
end
