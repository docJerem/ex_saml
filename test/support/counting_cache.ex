defmodule ExSaml.CountingCache do
  @moduledoc """
  Wraps `ExSaml.StubCache` and counts every operation per key, to assert the
  cost of a code path (review point 8: the debug machinery must be free when
  debug is off).
  """

  alias ExSaml.StubCache

  @counter :ex_saml_counting_cache

  @doc "Installs the cache and resets the counters."
  def install do
    StubCache.install()
    Application.put_env(:ex_saml, :cache, __MODULE__)
    reset()
  end

  def reset, do: :persistent_term.put(@counter, [])

  @doc "Every `{op, key}` recorded since the last reset, oldest first."
  def calls, do: @counter |> :persistent_term.get([]) |> Enum.reverse()

  @doc "Number of operations whose key belongs to `ExSaml.Debug`."
  def debug_reads do
    calls()
    |> Enum.count(fn {op, key} -> op in [:get, :ttl] and match?({ExSaml.Debug, _}, key) end)
  end

  defp record(op, key) do
    :persistent_term.put(@counter, [{op, key} | :persistent_term.get(@counter, [])])
  end

  def get(key), do: record(:get, key) && StubCache.get(key)
  def put(key, value, opts \\ []), do: record(:put, key) && StubCache.put(key, value, opts)

  def put_new!(key, value, opts \\ []),
    do: record(:put_new!, key) && StubCache.put_new!(key, value, opts)

  def take(key), do: record(:take, key) && StubCache.take(key)
  def delete(key), do: record(:delete, key) && StubCache.delete(key)
  def ttl(key), do: record(:ttl, key) && StubCache.ttl(key)
  def all(query \\ nil, opts \\ []), do: record(:all, query) && StubCache.all(query, opts)
end
