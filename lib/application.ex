defmodule UeberauthOIDC do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  def start(_type, _args) do
    children = [
      # Starts a worker by calling: Ueberauth.Strategy.OIDC.Worker.start_link(arg)
      # {Ueberauth.Strategy.OIDC.Worker, arg}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Ueberauth.Strategy.OIDC.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
