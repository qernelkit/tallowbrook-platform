defmodule Notify.Receipts.Signer do
  @moduledoc """
  Delivery receipts sent to partners (parcel delivered, signed for, left with a
  neighbour) are signed so partners can store them as evidence. Partners verify with
  the public key from the partner portal.
  """

  @spec sign(map(), binary()) :: %{receipt: String.t(), signature: String.t()}
  def sign(receipt, private_key) do
    receipt_json = Jason.encode!(receipt)
    signature = :crypto.sign(:eddsa, :none, receipt_json, [private_key, :ed25519])
    %{receipt: receipt_json, signature: Base.encode64(signature)}
  end

  @doc "The receipt key, base64 in the file at RECEIPT_KEY_PATH."
  @spec load_key() :: binary()
  def load_key do
    Application.fetch_env!(:notify, Notify.Receipts)
    |> Keyword.fetch!(:key_path)
    |> File.read!()
    |> String.trim()
    |> Base.decode64!()
  end
end
