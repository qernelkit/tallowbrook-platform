defmodule Notify.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        {Notify.APNs.ProviderToken, []},
        {Notify.FCM.AccessToken, []},
        {Notify.Store.PayloadVault, []},
        {Task.Supervisor, name: Notify.TaskSupervisor},
        {Bandit, plug: NotifyWeb.Endpoint, port: NotifyWeb.Endpoint.port()}
      ] ++ pools()

    Supervisor.start_link(children, strategy: :one_for_one, name: Notify.Supervisor)
  end

  defp pools do
    if Application.get_env(:notify, :start_pools, true) do
      [Notify.Push.Pool, Notify.Webhooks.Client.Pool]
    else
      []
    end
  end
end
