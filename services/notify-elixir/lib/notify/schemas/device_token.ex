defmodule Notify.Schemas.DeviceToken do
  @moduledoc """
  A push registration: which app instance gets notifications, through APNs or FCM.
  The token is the routing id the platform issued, not a credential.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "device_tokens" do
    field(:platform, Ecto.Enum, values: [:apns, :fcm])
    field(:token, :string)
    field(:customer_id, :string)
    field(:device_name, :string)
    field(:topics, {:array, :string}, default: [])
    field(:last_seen_at, :utc_datetime)
    timestamps(type: :utc_datetime)
  end

  @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
  def changeset(registration, attrs) do
    registration
    |> cast(attrs, [:platform, :token, :customer_id, :device_name, :topics, :last_seen_at])
    |> validate_required([:platform, :token, :customer_id])
    |> validate_length(:token, min: 32, max: 4096)
    |> validate_subset(:topics, ~w(out_for_delivery delayed delivered customs collection))
  end

  @type t :: %__MODULE__{}
end
