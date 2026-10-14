defmodule Notify.Schemas.DeviceTokenTest do
  use ExUnit.Case, async: true

  alias Notify.Schemas.DeviceToken

  @valid %{platform: :apns, token: String.duplicate("a1", 32), customer_id: "c-1001", topics: ["delayed"]}

  test "accepts a complete registration" do
    assert DeviceToken.changeset(%DeviceToken{}, @valid).valid?
  end

  test "rejects unknown topics" do
    changeset = DeviceToken.changeset(%DeviceToken{}, %{@valid | topics: ["weather"]})
    refute changeset.valid?
  end

  test "requires a platform" do
    changeset = DeviceToken.changeset(%DeviceToken{}, Map.delete(@valid, :platform))
    assert {"can't be blank", _} = changeset.errors[:platform]
  end
end
