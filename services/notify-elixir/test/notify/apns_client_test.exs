defmodule Notify.APNs.ClientTest do
  use ExUnit.Case, async: true

  test "parcel alerts thread by tracking number" do
    alert = Notify.APNs.Client.parcel_alert("TB123456789GB", "Out for delivery", "Arriving 10:00-12:00")
    assert alert["aps"]["thread-id"] == "TB123456789GB"
    assert alert["aps"]["alert"]["title"] == "Out for delivery"
    assert alert["tracking_number"] == "TB123456789GB"
  end
end
