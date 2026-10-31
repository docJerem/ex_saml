defmodule ExSaml.Cache do
  @moduledoc false

  # The only module that calls the Nebulex 3 cache configured with
  # `config :ex_saml, cache: MyApp.Cache`.
  #
  # Nebulex 3 returns `{:ok, value}` and `{:error, reason}` tuples, and its
  # bang functions return the bare value. This module keeps the contract the
  # ExSaml cache modules expose: a bare value, `nil` for a missing key, and an
  # exception for any other error.

  @doc "Returns the value for `key`, or `nil` when the key is missing."
  def get(key), do: cache().get!(key)

  @doc "Stores `value` under `key`."
  def put(key, value, opts), do: cache().put!(key, value, opts)

  @doc "Deletes `key`."
  def delete(key), do: cache().delete!(key)

  @doc "Atomically returns and deletes the value for `key`, or `nil` when the key is missing."
  def take(key), do: key |> cache().take() |> value_or_nil()

  @doc "Returns the remaining TTL of `key`, or `nil` when the key is missing."
  def ttl(key), do: key |> cache().ttl() |> value_or_nil()

  @doc """
  Stores `value` under `key` only if `key` is missing. Returns `true`, and
  raises a `Nebulex.Error` when `key` already exists.
  """
  def put_new!(key, value, opts) do
    if cache().put_new!(key, value, opts) do
      true
    else
      # The key is left out of the error: it can be a secret, such as an
      # authorization code.
      raise Nebulex.Error, reason: :key_already_exists, command: :put_new
    end
  end

  @doc "Returns the entries matching the Nebulex 3 `query_spec` (all entries by default)."
  def get_all(query_spec \\ []), do: cache().get_all!(query_spec)

  defp value_or_nil({:ok, value}), do: value
  defp value_or_nil({:error, %Nebulex.KeyError{}}), do: nil
  defp value_or_nil({:error, reason}), do: raise(reason)

  defp cache, do: Application.get_env(:ex_saml, :cache)
end
