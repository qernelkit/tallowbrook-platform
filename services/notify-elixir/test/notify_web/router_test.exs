defmodule NotifyWeb.RouterTest do
  use ExUnit.Case, async: true
  import Plug.Test

  test "health check" do
    conn = conn(:get, "/health") |> NotifyWeb.Router.call(NotifyWeb.Router.init([]))
    assert conn.status == 200
    assert conn.resp_body == "ok"
  end

  test "unknown paths are 404" do
    conn = conn(:get, "/nope") |> NotifyWeb.Router.call(NotifyWeb.Router.init([]))
    assert conn.status == 404
  end

  test "subscribing needs a session token" do
    conn = conn(:post, "/v1/subscriptions", %{"platform" => "apns"}) |> NotifyWeb.Router.call(NotifyWeb.Router.init([]))
    assert conn.status == 401
  end
end
