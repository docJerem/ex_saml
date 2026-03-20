defmodule ExSaml.State.Cache do
  @moduledoc """
  Stores SAML assertions using a Nebulex cache backend.

  Suitable for distributed environments. Assertions have a default TTL of 5 minutes.

  ## Configuration

      config :ex_saml, ExSaml.State,
        store: ExSaml.State.Cache

      config :ex_saml, cache: MyApp.Cache
  """
  alias ExSaml.AssertionCache

  @behaviour ExSaml.State.Store

  @ttl :timer.minutes(5)

  @impl ExSaml.State.Store
  def init(opts \\ []), do: opts

  @doc "Lists all cached assertions as `{key, value}` tuples."
  def list_assertions(), do: AssertionCache.all(nil, return: {:key, :value})

  @doc "Returns the remaining TTL for the given assertion key."
  def ttl_assertion({_, _} = key), do: AssertionCache.ttl(key)

  @impl ExSaml.State.Store
  def get_assertion(_conn, assertion_key, _), do: AssertionCache.get(assertion_key)

  @impl ExSaml.State.Store
  def put_assertion(conn, assertion_key, assertion, _) do
    AssertionCache.put(assertion_key, assertion, ttl: @ttl)

    conn
  end

  @impl ExSaml.State.Store
  def delete_assertion(conn, assertion_key, _) do
    AssertionCache.delete(assertion_key)

    conn
  end
end
