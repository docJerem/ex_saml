defmodule ExSaml.ErrorCache do
  @moduledoc """
  TTL-based cache for sign-in failures, the failure-side counterpart of
  `ExSaml.AuthorizationCodeCache`.

  When the assertion consumer service cannot complete a sign-in, `ExSaml.SPHandler`
  stores a `%ExSaml.Error{}` under a random `error_id` and redirects the browser
  to the target URL with `?error_id=<id>`. The consumer redeems it once with
  `ExSaml.Error.get_from_id/1`, exactly like it redeems a `code` with
  `ExSaml.Assertion.get_from_code/1`.

  Uses the cache module configured via `config :ex_saml, cache: MyApp.Cache`.
  The TTL defaults to 5 minutes and can be changed with
  `config :ex_saml, error_ttl: :timer.minutes(2)`.
  """

  @default_ttl :timer.minutes(5)

  @doc "Returns the TTL applied to error entries."
  @spec ttl() :: non_neg_integer()
  def ttl, do: Application.get_env(:ex_saml, :error_ttl, @default_ttl)

  @doc "Returns the remaining TTL of a stored error."
  def ttl(id), do: cache().ttl(cache_key(id))

  @doc "Retrieves the error for the given id without consuming it."
  def get(id), do: cache().get(cache_key(id))

  @doc "Stores an error with the default TTL (or `ttl:` from opts)."
  def put(id, error, opts \\ []) do
    ttl = Keyword.get(opts, :ttl, ttl())
    cache().put(cache_key(id), error, ttl: ttl)
  end

  @doc "Stores only if the id is free. Raises if it already exists."
  def put_new!(id, error, opts \\ []) do
    ttl = Keyword.get(opts, :ttl, ttl())
    cache().put_new!(cache_key(id), error, ttl: ttl)
  end

  @doc "Atomically retrieves and deletes the error (single-use)."
  def take(id), do: cache().take(cache_key(id))

  @doc "Deletes the error for the given id."
  def delete(id), do: cache().delete(cache_key(id))

  defp cache, do: Application.get_env(:ex_saml, :cache)

  defp cache_key(id), do: {__MODULE__, id}
end
