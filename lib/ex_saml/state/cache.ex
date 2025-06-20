defmodule ExSaml.State.Cache do
  @moduledoc false
  alias ExSaml.AssertionCache

  @behaviour ExSaml.State.Store

  @ttl :timer.minutes(5)

  @impl ExSaml.State.Store
  def init(opts \\ []), do: opts

  def list_assertions(), do: AssertionCache.all(nil, return: {:key, :value})

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
