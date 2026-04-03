defmodule ExSaml.AuthorizationCodeCache do
  @moduledoc """
  TTL-based authorization code cache.

  Stores authorization codes during the SAML authentication flow with a 30-second TTL.
  Uses the cache module configured via `config :ex_saml, cache: MyApp.Cache`.

  The `take/1` function atomically retrieves and deletes the code,
  ensuring single-use consumption.
  """

  @ttl :timer.seconds(30)

  @doc "Returns the default TTL for authorization codes (30 seconds)."
  def ttl, do: @ttl

  @doc "Retrieves the authorization code data for the given key."
  def get(key), do: cache().get(cache_key(key))

  @doc "Stores authorization code data with the default TTL."
  def put(key, value, opts \\ []) do
    ttl = Keyword.get(opts, :ttl, @ttl)
    cache().put(cache_key(key), value, ttl: ttl)
  end

  @doc "Atomically retrieves and deletes the authorization code (single-use)."
  def take(key), do: cache().take(cache_key(key))

  @doc "Stores only if the key doesn't already exist. Returns `:ok` or `{:error, :already_exists}`."
  def put_new!(key, value) do
    ck = cache_key(key)

    if cache().get(ck) do
      {:error, :already_exists}
    else
      cache().put(ck, value, ttl: @ttl)
      :ok
    end
  end

  defp cache, do: Application.get_env(:ex_saml, :cache)

  defp cache_key(key), do: {__MODULE__, key}
end
