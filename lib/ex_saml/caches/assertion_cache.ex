defmodule ExSaml.AssertionCache do
  @moduledoc false
  alias ExSaml.Cache

  def all(query_spec \\ []), do: Cache.get_all(query_spec)

  def ttl(key), do: Cache.ttl(cache_key(key))

  def get(key), do: Cache.get(cache_key(key))

  def put(key, assertion, ttl: ttl),
    do: Cache.put(cache_key(key), assertion, ttl: ttl)

  def delete(key), do: Cache.delete(cache_key(key))

  @doc "Atomically retrieves and deletes the assertion (anti-replay)."
  def take(key), do: Cache.take(cache_key(key))

  defp cache_key(key), do: {__MODULE__, key}
end
