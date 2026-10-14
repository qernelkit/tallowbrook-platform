defmodule Notify.Partners.ApiKeys do
  @moduledoc """
  API keys partners use to call the notify API. Only a verifier is stored: a salt and a
  derived digest. The key itself is shown to the partner once, at issue.
  """

  @iterations 210_000
  @prefix "tbn_"

  @type verifier :: %{salt: binary(), digest: binary()}

  @spec issue() :: {String.t(), verifier()}
  def issue do
    key = @prefix <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
    salt = :crypto.strong_rand_bytes(16)
    {key, %{salt: salt, digest: digest(key, salt)}}
  end

  @spec verify(String.t(), verifier()) :: boolean()
  def verify(@prefix <> _ = key, %{salt: salt, digest: expected}) do
    Plug.Crypto.secure_compare(digest(key, salt), expected)
  end

  def verify(_key, _verifier), do: false

  defp digest(key, salt), do: :crypto.pbkdf2_hmac(:sha256, key, salt, @iterations, 32)
end
