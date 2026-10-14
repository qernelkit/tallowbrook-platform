defmodule NotifyWeb.SubscriberToken do
  @moduledoc """
  The subscribe endpoint takes the customer's session token from the identity service
  and only trusts what that service signed.
  """

  @spec verify(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def verify(token) do
    case JOSE.JWT.verify_strict(identity_jwk(), ["ES256"], token) do
      {true, %JOSE.JWT{fields: %{"sub" => customer_id, "exp" => exp}}, _jws} ->
        if exp > System.system_time(:second), do: {:ok, customer_id}, else: {:error, :expired}

      {true, _jwt, _jws} ->
        {:error, :missing_claims}

      _ ->
        {:error, :invalid}
    end
  rescue
    _ -> {:error, :malformed}
  end

  defp identity_jwk do
    JOSE.JWK.from_pem(Application.fetch_env!(:notify, :identity_token_key))
  end
end
