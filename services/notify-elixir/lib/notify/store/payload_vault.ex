defmodule Notify.Store.PayloadVault do
  @moduledoc """
  Notification payloads waiting for a retry are kept encrypted, because they carry
  names and addresses. The key is read from PAYLOAD_VAULT_KEY_PATH at start-up.
  """
  use Agent

  @cipher :aes_256_gcm
  @aad "notify-payload-v1"

  def start_link(_opts) do
    Agent.start_link(fn -> %{key: load_key(), entries: %{}} end, name: __MODULE__)
  end

  @spec put(String.t(), binary()) :: :ok
  def put(id, payload) do
    Agent.update(__MODULE__, fn state -> put_in(state, [:entries, id], seal(state.key, payload)) end)
  end

  @spec take(String.t()) :: {:ok, binary()} | :error
  def take(id) do
    Agent.get_and_update(__MODULE__, fn state ->
      case Map.pop(state.entries, id) do
        {nil, _} -> {:error, state}
        {sealed, rest} -> {open(state.key, sealed), %{state | entries: rest}}
      end
    end)
  end

  def seal(key, payload) do
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(@cipher, key, iv, payload, @aad, true)
    iv <> tag <> ciphertext
  end

  def open(key, <<iv::binary-12, tag::binary-16, ciphertext::binary>>) do
    case :crypto.crypto_one_time_aead(@cipher, key, iv, ciphertext, @aad, tag, false) do
      :error -> :error
      payload -> {:ok, payload}
    end
  end

  defp load_key do
    case Application.get_env(:notify, __MODULE__, [])[:key_path] do
      nil -> :crypto.strong_rand_bytes(32)
      path -> path |> File.read!() |> String.trim() |> Base.decode64!()
    end
  end
end
