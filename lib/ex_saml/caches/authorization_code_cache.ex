defmodule ExSaml.AuthorizationCodeCache do
  @moduledoc """
  TTL-based authorization code cache.

  Stores authorization codes during the SAML authentication flow with a 30-second TTL.
  Uses the cache module configured via `config :ex_saml, cache: MyApp.Cache`.

  The `take/1` function atomically retrieves and deletes the code,
  ensuring single-use consumption.
  """
  alias ExSaml.Cache

  @ttl :timer.seconds(30)

  @doc "Returns the default TTL for authorization codes (30 seconds)."
  def ttl, do: @ttl

  @doc "Retrieves the authorization code data for the given key."
  def get(key), do: Cache.get(cache_key(key))

  @doc "Stores authorization code data with the default TTL."
  def put(key, value, opts \\ []) do
    ttl = Keyword.get(opts, :ttl, @ttl)
    Cache.put(cache_key(key), value, ttl: ttl)
  end

  @doc "Atomically retrieves and deletes the authorization code (single-use)."
  def take(key), do: Cache.take(cache_key(key))

  @doc """
  Stores authorization code data only if the key doesn't already exist.

  Returns `true`, and raises a `Nebulex.Error` with the reason
  `:key_already_exists` when the key already exists.
  """
  def put_new!(key, value, opts \\ []) do
    ttl = Keyword.get(opts, :ttl, @ttl)

    ck = cache_key(key)

    Cache.put_new!(ck, value, ttl: ttl)
  end

  defp cache_key(key), do: {__MODULE__, key}
end
