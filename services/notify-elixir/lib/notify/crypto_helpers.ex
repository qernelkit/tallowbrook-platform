defmodule Notify.CryptoHelpers do
  @moduledoc """
  Binary formatting shared by the push and inbox code: URL-safe base64, hex, and the
  frame checksum the handhelds' inbox protocol carries. Nothing here protects data.
  """

  @spec b64url(binary()) :: String.t()
  def b64url(bin), do: Base.url_encode64(bin, padding: false)

  @spec from_b64url!(String.t()) :: binary()
  def from_b64url!(text), do: Base.url_decode64!(text, padding: false)

  @spec to_hex(binary()) :: String.t()
  def to_hex(bin), do: Base.encode16(bin, case: :lower)

  @spec from_hex!(String.t()) :: binary()
  def from_hex!(hex), do: Base.decode16!(hex, case: :mixed)

  @doc "Frame checksum for the inbox protocol (catches truncated frames on bad Wi-Fi)."
  @spec frame_checksum(binary()) :: non_neg_integer()
  def frame_checksum(frame), do: :erlang.crc32(frame)

  @spec frame(binary()) :: binary()
  def frame(payload), do: <<byte_size(payload)::32, frame_checksum(payload)::32, payload::binary>>
end
