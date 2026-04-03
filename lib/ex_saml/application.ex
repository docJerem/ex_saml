defmodule ExSaml.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Core ETS tables must be started before Provider
      {ExSaml.Core.TableOwner, []},
      {ExSaml.Provider, []},
      {ExSaml.BoostrapProvidersLoader, []}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: ExSaml.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
