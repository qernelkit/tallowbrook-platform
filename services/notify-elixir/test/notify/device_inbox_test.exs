defmodule Notify.Inbox.DeviceInboxTest do
  use ExUnit.Case, async: true

  alias Notify.Inbox.DeviceInbox

  test "partitions are bounded" do
    assert DeviceInbox.partitions() == 16
  end
end
