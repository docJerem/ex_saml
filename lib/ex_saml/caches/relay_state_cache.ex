defmodule ExSaml.RelayStateCache do
  @moduledoc """
  TTL-based relay state cache with anti-replay protection.

  Stores relay state data during the SAML authentication flow. Uses the cache module
  configured via `config :ex_saml, cache: MyApp.Cache`.

  The `take/1` function atomically retrieves and deletes the relay state,
  preventing replay attacks.

  The debug hooks deliberately do not set `debug_id`: it comes from the process
  context, so an entry lands in the report for the flow that is running rather
  than in one keyed by the raw RelayState — which for an IdP-initiated flow is
  not our identifier at all.
  """

  alias ExSaml.Debug

  @doc "Returns the remaining TTL for the given relay state key."
  def ttl(key), do: assertion_cache().ttl(cache_key(key))

  @doc "Retrieves the relay state data for the given key."
  def get(key), do: assertion_cache().get(cache_key(key))

  @doc "Stores relay state data with a TTL."
  def put(key, assertion, ttl: ttl),
    do: assertion_cache().put(cache_key(key), assertion, ttl: ttl)

  @doc "Deletes the relay state for the given key."
  def delete(key) do
    result = assertion_cache().delete(cache_key(key))
    Debug.log(:relay_state_deleted, %{relay_state: key})
    result
  end

  @doc "Atomically retrieves and deletes the relay state (anti-replay)."
  def take(key) do
    value = assertion_cache().take(cache_key(key))

    Debug.log(:relay_state_taken, fn ->
      %{relay_state: key, hit: not is_nil(value), value: value}
    end)

    value
  end

  defp assertion_cache, do: Application.get_env(:ex_saml, :cache)

  defp cache_key(key), do: {__MODULE__, key}
end
