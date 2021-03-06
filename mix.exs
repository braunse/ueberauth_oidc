defmodule Ueberauth.Strategy.OIDC.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_oidc,
      version: "0.1.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
      # mod: {Ueberauth.Strategy.OIDC.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ueberauth, "~> 0.6.3"},
      {:oauth2, "~> 2.0.0"},
      {:jason, "~> 1.2.2"},
      {:mock, "~> 0.3.6", only: [:test]}
    ]
  end
end
