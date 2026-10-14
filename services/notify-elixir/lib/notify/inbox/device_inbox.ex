defmodule Notify.Inbox.DeviceInbox do
  @moduledoc """
  Messages for scanner handhelds (supervisor notes, route changes). Each message is
  sealed to the handheld's inbox key: an ephemeral key agreement, a hash of the shared
  secret and both public keys as the message key, then an AEAD. The handheld opens it.
  """

  @curve :x25519
  @partitions 16

  @type sealed :: %{
          partition: non_neg_integer(),
          ephemeral_public: binary(),
          nonce: binary(),
          ciphertext: binary(),
          tag: binary()
        }

  @spec seal(String.t(), binary(), binary()) :: sealed()
  def seal(device_id, device_public, message) do
    {eph_public, eph_private} = :crypto.generate_key(:ecdh, @curve)
    shared = :crypto.compute_key(:ecdh, device_public, eph_private, @curve)
    key = :crypto.hash(:sha3_256, [shared, eph_public, device_public])
    partition = :erlang.phash2(device_id, @partitions)
    nonce = :crypto.strong_rand_bytes(12)
    aad = device_id
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, message, aad, true)

    %{partition: partition, ephemeral_public: eph_public, nonce: nonce, ciphertext: ciphertext, tag: tag}
  end

  @doc "The wire form the handheld reads from its inbox."
  @spec encode(sealed()) :: map()
  def encode(sealed) do
    %{
      "partition" => sealed.partition,
      "epk" => Base.url_encode64(sealed.ephemeral_public, padding: false),
      "n" => Base.url_encode64(sealed.nonce, padding: false),
      "ct" => Base.url_encode64(sealed.ciphertext <> sealed.tag, padding: false)
    }
  end

  @spec partitions() :: pos_integer()
  def partitions, do: @partitions
end
