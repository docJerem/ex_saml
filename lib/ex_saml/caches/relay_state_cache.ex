defmodule ExSaml.RelayStateCache do
  @moduledoc """
  TTL-based relay state cache with anti-replay protection.

  Stores relay state data during the SAML authentication flow. Uses the cache module
  configured via `config :ex_saml, cache: MyApp.Cache`.

  The `take/1` function atomically retrieves and deletes the relay state,
  preventing replay attacks.
  """

  @doc "Returns the remaining TTL for the given relay state key."
  def ttl(key), do: assertion_cache().ttl(cache_key(key))

  @doc "Retrieves the relay state data for the given key."
  def get(key), do: assertion_cache().get(cache_key(key))

  @doc "Stores relay state data with a TTL."
  def put(key, assertion, ttl: ttl),
    do: assertion_cache().put(cache_key(key), assertion, ttl: ttl)

  @doc "Deletes the relay state for the given key."
  def delete(key), do: assertion_cache().delete(cache_key(key))

  @doc "Atomically retrieves and deletes the relay state (anti-replay)."
  def take(key), do: assertion_cache().take(cache_key(key))

  defp assertion_cache(), do: Application.get_env(:ex_saml, :cache)

  defp cache_key(key), do: {__MODULE__, key}
end
