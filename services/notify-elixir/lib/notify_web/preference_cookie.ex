defmodule NotifyWeb.PreferenceCookie do
  @moduledoc """
  The preference centre keeps a customer's choices in a cookie between visits, so the
  page works without an account session. The cookie is encrypted: it holds the email.
  """
  alias NotifyWeb.Secrets

  @cookie "tb_prefs"
  @max_age 60 * 60 * 24 * 180

  @spec cookie_name() :: String.t()
  def cookie_name, do: @cookie

  @spec put(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def put(conn, prefs) do
    sealed =
      Plug.Crypto.MessageEncryptor.encrypt(
        Jason.encode!(prefs),
        Secrets.derive("prefs cookie"),
        Secrets.derive("prefs cookie sign")
      )

    Plug.Conn.put_resp_cookie(conn, @cookie, sealed, max_age: @max_age, http_only: true, secure: true, same_site: "Lax")
  end

  @spec get(Plug.Conn.t()) :: map()
  def get(conn) do
    with sealed when is_binary(sealed) <- Plug.Conn.fetch_cookies(conn).cookies[@cookie],
         {:ok, json} <-
           Plug.Crypto.MessageEncryptor.decrypt(
             sealed,
             Secrets.derive("prefs cookie"),
             Secrets.derive("prefs cookie sign")
           ),
         {:ok, prefs} <- Jason.decode(json) do
      prefs
    else
      _ -> %{}
    end
  end
end
