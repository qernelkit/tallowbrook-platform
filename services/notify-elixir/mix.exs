defmodule Notify.MixProject do
  use Mix.Project

  def project do
    [
      app: :notify,
      version: "2.7.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {Notify.Application, []},
      extra_applications: [:logger, :crypto, :public_key, :ssl]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:bandit, "~> 1.12"},
      {:ecto, "~> 3.14"},
      {:finch, "~> 0.23.0"},
      {:jason, "~> 1.4"},
      {:jose, "~> 1.11"},
      {:plug, "~> 1.20"},
      {:plug_crypto, "~> 2.2"}
    ]
  end
end
