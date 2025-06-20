defmodule ExSaml.BoostrapProvidersLoader do
  @moduledoc """
  GenServer that loads SAML providers after the application and database are ready.
  Uses retry logic to handle cases where the database isn't available yet.
  """
  use GenServer
  require Logger

  # 1 second
  @initial_delay 1000
  # 5 seconds
  @retry_delay 5000
  # Maximum number of retries
  @max_retries 10

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(_opts) do
    Logger.info("[ExSaml.BoostrapProvidersLoader] Starting provider loader...")

    # Schedule the initial load attempt
    Process.send_after(self(), :load_providers, @initial_delay)

    {:ok, %{retries: 0, loaded: false}}
  end

  def handle_info(:load_providers, %{retries: retries, loaded: false} = state) do
    case ExSaml.ProvidersLoader.load() do
      :ok ->
        Logger.info("[ExSaml.BoostrapProvidersLoader] Providers loaded successfully")
        {:noreply, %{state | loaded: true}}

      {:error, reason} when retries < @max_retries ->
        Logger.warning(
          "[ExSaml.BoostrapProvidersLoader] Failed to load providers (attempt #{retries + 1}): #{inspect(reason)}. Retrying in #{@retry_delay}ms..."
        )

        Process.send_after(self(), :load_providers, @retry_delay)
        {:noreply, %{state | retries: retries + 1}}

      {:error, reason} ->
        Logger.error(
          "[ExSaml.BoostrapProvidersLoader] Failed to load providers after #{@max_retries} attempts: #{inspect(reason)}"
        )

        {:noreply, state}
    end
  end

  def handle_info(:load_providers, %{loaded: true} = state) do
    # Already loaded, ignore
    {:noreply, state}
  end

  # Public API to check if providers are loaded
  def loaded? do
    case GenServer.call(__MODULE__, :status, 1000) do
      %{loaded: true} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  # Public API to force reload
  def reload do
    GenServer.cast(__MODULE__, :reload)
  end

  def handle_call(:status, _from, state) do
    {:reply, state, state}
  end

  def handle_cast(:reload, state) do
    Logger.info("[ExSaml.BoostrapProvidersLoader] Manual reload requested")
    Process.send(self(), :load_providers, [])
    {:noreply, %{state | loaded: false, retries: 0}}
  end
end
