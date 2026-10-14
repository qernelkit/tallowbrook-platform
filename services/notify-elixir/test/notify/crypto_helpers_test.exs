defmodule Notify.CryptoHelpersTest do
  use ExUnit.Case, async: true

  alias Notify.CryptoHelpers

  test "base64url round-trips without padding" do
    bin = <<0xFB, 0xFF, 0x00, 0x10>>
    encoded = CryptoHelpers.b64url(bin)
    refute String.contains?(encoded, "=")
    assert CryptoHelpers.from_b64url!(encoded) == bin
  end

  test "hex accepts either case" do
    assert CryptoHelpers.from_hex!("0aFF") == <<0x0A, 0xFF>>
    assert CryptoHelpers.to_hex(<<0x0A, 0xFF>>) == "0aff"
  end

  test "frames carry length and checksum" do
    <<len::32, sum::32, payload::binary>> = CryptoHelpers.frame("hello")
    assert len == 5
    assert payload == "hello"
    assert sum == CryptoHelpers.frame_checksum("hello")
  end
end
