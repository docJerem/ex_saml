defmodule ExSaml.StubCache do
  @moduledoc """
  In-memory stand-in for the Nebulex cache configured via `config :ex_saml, cache: …`.

  Backed by an `Agent` so it can be shared across processes within a test. TTLs
  are recorded but never enforced. Use `install/0` in a test `setup` to point
  `:ex_saml, :cache` at this module for the duration of the test.
  """

  use Agent

  @doc "Starts the agent (idempotent) and configures `:ex_saml, :cache` to use it."
  def install do
    case Agent.start(fn -> %{} end, name: __MODULE__) do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> reset()
    end

    previous = Application.get_env(:ex_saml, :cache)
    Application.put_env(:ex_saml, :cache, __MODULE__)

    ExUnit.Callbacks.on_exit(fn ->
      if previous,
        do: Application.put_env(:ex_saml, :cache, previous),
        else: Application.delete_env(:ex_saml, :cache)
    end)

    :ok
  end

  @doc "Empties the cache."
  def reset, do: Agent.update(__MODULE__, fn _ -> %{} end)

  @doc "Returns every `{key, value}` pair."
  def dump, do: all(nil, return: {:key, :value})

  # -- Nebulex-like API -------------------------------------------------------

  def get(key), do: Agent.get(__MODULE__, fn s -> s |> Map.get(key) |> value() end)

  def put(key, value, opts \\ []) do
    Agent.update(__MODULE__, &Map.put(&1, key, {value, Keyword.get(opts, :ttl, :infinity)}))
    :ok
  end

  def put_new!(key, value, opts \\ []) do
    entry = {value, Keyword.get(opts, :ttl, :infinity)}

    Agent.get_and_update(__MODULE__, fn s ->
      if Map.has_key?(s, key), do: {:exists, s}, else: {:ok, Map.put(s, key, entry)}
    end)
    |> case do
      :ok -> :ok
      :exists -> raise "key already exists: #{inspect(key)}"
    end
  end

  def take(key) do
    Agent.get_and_update(__MODULE__, fn s ->
      {s |> Map.get(key) |> value(), Map.delete(s, key)}
    end)
  end

  def delete(key) do
    Agent.update(__MODULE__, &Map.delete(&1, key))
    :ok
  end

  def ttl(key) do
    Agent.get(__MODULE__, fn s ->
      case Map.get(s, key) do
        {_, ttl} -> ttl
        nil -> nil
      end
    end)
  end

  def all(_query \\ nil, opts \\ []) do
    state = Agent.get(__MODULE__, & &1)
    select(state, Keyword.get(opts, :return, :key))
  end

  defp select(state, :key), do: Map.keys(state)
  defp select(state, :value), do: state |> Map.values() |> Enum.map(&value/1)
  defp select(state, {:key, :value}), do: Enum.map(state, fn {k, entry} -> {k, value(entry)} end)

  defp value({v, _ttl}), do: v
  defp value(nil), do: nil
end

defmodule ExSaml.RaisingCache do
  @moduledoc "Cache stub whose every operation raises, to prove debug never breaks the flow."

  def get(_), do: raise("cache down")
  def put(_, _, _ \\ []), do: raise("cache down")
  def put_new!(_, _, _ \\ []), do: raise("cache down")
  def take(_), do: raise("cache down")
  def delete(_), do: raise("cache down")
  def ttl(_), do: raise("cache down")
  def all(_ \\ nil, _ \\ []), do: raise("cache down")
end
