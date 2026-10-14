defmodule NotifyWeb.Router do
  @moduledoc false
  use Plug.Router
  require Logger

  alias NotifyWeb.{PreferenceCookie, SubscriberToken, UnsubscribeLink}

  plug(:match)
  plug(:dispatch)

  get "/health" do
    send_resp(conn, 200, "ok")
  end

  # The customer app subscribes a device after sign-in.
  post "/v1/subscriptions" do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, customer_id} <- SubscriberToken.verify(token),
         %{"platform" => platform, "token" => device_token} <- conn.body_params do
      Logger.info("Subscribed #{platform} device", customer_id: customer_id)
      _ = device_token
      send_json(conn, 201, %{"status" => "subscribed"})
    else
      _ -> send_json(conn, 401, %{"error" => "unauthorized"})
    end
  end

  get "/unsubscribe" do
    conn = fetch_query_params(conn)

    case UnsubscribeLink.parse(conn.query_params["t"] || "") do
      {:ok, {subscriber_id, topic}} ->
        Logger.info("Unsubscribed from #{topic}", subscriber_id: subscriber_id)
        send_resp(conn, 200, "You won't get #{topic} emails any more.")

      :error ->
        send_resp(conn, 400, "This link has expired. Use the preference centre instead.")
    end
  end

  # RFC 8058 one-click: mail clients POST to the same URL.
  post "/unsubscribe" do
    conn = fetch_query_params(conn)

    case UnsubscribeLink.parse(conn.query_params["t"] || "") do
      {:ok, _} -> send_resp(conn, 204, "")
      :error -> send_resp(conn, 400, "")
    end
  end

  get "/preferences" do
    send_json(conn, 200, PreferenceCookie.get(conn))
  end

  put "/preferences" do
    prefs = Map.take(conn.body_params, ["email", "out_for_delivery", "delayed", "marketing"])

    conn
    |> PreferenceCookie.put(prefs)
    |> send_json(200, prefs)
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
