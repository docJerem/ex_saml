defmodule ExSaml.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  alias ExSaml.Core.Xml.SafeXml.AtomBudget

  @impl true
  def start(_type, _args) do
    _ = AtomBudget.init()

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
