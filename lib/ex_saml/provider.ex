defmodule ExSaml.Provider do
  @moduledoc """
  SAML 2.0 Service Provider

  This should be added to the hosting Phoenix/Plug application's supervision tree.
  This GenServer initializes the SP configuration and loads the IDP medata XML
  containing information on how to communicate with the IDP.

  ```elixir
  # application.ex

    children = [
      # ...
      worker(ExSaml.Provider, []),
    ]
  ```

  Check README.md `Configuration` section.
  """

  use GenServer
  require Logger

  require ExSaml.Esaml
  alias ExSaml.{State}

  @doc false
  def start_link(gs_opts \\ []) do
    GenServer.start_link(__MODULE__, [], gs_opts)
  end

  @doc false
  def init([]) do
    store_env = Application.get_env(:ex_saml, ExSaml.State, [])
    store_provider = store_env[:store] || ExSaml.State.ETS
    store_opts = store_env[:opts] || []
    State.init(store_provider, store_opts)

    opts = opts()

    # must be done prior to loading the providers
    idp_id_from =
      case opts[:idp_id_from] do
        nil ->
          :path_segment

        value when value in [:subdomain, :path_segment] ->
          value

        unknown ->
          Logger.warning(
            "[ExSaml] invalid_data idp_id_from: #{inspect(unknown)}. Using :path_segment"
          )

          :path_segment
      end

    Application.put_env(:ex_saml, :idp_id_from, idp_id_from)
    :esaml_util.start_ets()

    refresh_providers()
  end

  @doc """
  Refresh the provider configuration, allowing runtime-configuration to be applied after
  application start.
  """
  def refresh_providers do
    opts = opts()

    service_providers = ExSaml.SpData.load_providers(opts[:service_providers] || [])

    identity_providers =
      ExSaml.IdpData.load_providers(opts[:identity_providers] || [], service_providers)

    Application.put_env(:ex_saml, :service_providers, service_providers)
    Application.put_env(:ex_saml, :identity_providers, identity_providers)

    {:ok, %{}}
  end

  defp opts, do: Application.get_env(:ex_saml, ExSaml.Provider, [])
end
