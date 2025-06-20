defmodule ExSaml.ProvidersLoader do
  @moduledoc """
  Module to configure SAMLY using SP and IDP present in DB
  """
  alias ExSaml.Provider
  require Logger

  def load do
    Logger.info("[ExSaml.ProvidersLoader] Loading providers...")

    case list_samly_providers() do
      {:ok, providers} ->
        Application.put_env(:ex_saml, Provider, providers)
        Provider.refresh_providers()
        Logger.info("[ExSaml.ProvidersLoader] Providers loaded and refreshed successfully")
        :ok

      {:error, reason} = error ->
        Logger.error("[ExSaml.ProvidersLoader] Failed to load providers: #{inspect(reason)}")
        error
    end
  end

  def list_samly_providers do
    try do
      base_config = Application.get_env(:ex_saml, Provider, [])

      service_providers = ExSaml.list_service_providers()
      identity_providers = ExSaml.list_identity_providers()

      providers =
        base_config
        |> Keyword.put(:service_providers, service_providers)
        |> Keyword.put(:identity_providers, identity_providers)

      {:ok, providers}
    rescue
      e in RuntimeError ->
        case Exception.message(e) do
          "could not lookup Ecto repo" <> _ ->
            {:error, :repo_not_ready}

          _ ->
            {:error, {:runtime_error, Exception.message(e)}}
        end

      error ->
        {:error, {:unexpected_error, error}}
    end
  end
end
