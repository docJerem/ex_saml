defmodule ExSaml.RelayStateCache do
  @moduledoc false

  def ttl(key), do: assertion_cache().ttl(cache_key(key))

  def get(key), do: assertion_cache().get(cache_key(key))

  def put(key, assertion, ttl: ttl),
    do: assertion_cache().put(cache_key(key), assertion, ttl: ttl)

  def delete(key), do: assertion_cache().delete(cache_key(key))

  defp assertion_cache(), do: Application.get_env(:ex_saml, :cache)

  defp cache_key(key), do: {__MODULE__, key}
end
