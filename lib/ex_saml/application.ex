defmodule ExSaml.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Starts a worker by calling: ExSaml.Worker.start_link(arg)
      # {ExSaml.Worker, arg}
      {ExSaml.Provider, []},
      {ExSaml.BoostrapProvidersLoader, []},
      ExSaml.AssertionCache,
      ExSaml.RelayStateCache,
      ExSaml.AuthorizationCodeCache
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExSaml.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
