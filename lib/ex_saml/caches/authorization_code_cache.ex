defmodule ExSaml.AuthorizationCodeCache do
  @moduledoc """
  TTL-based authorization code cache.

  Stores authorization codes during the SAML authentication flow with a 30-second TTL.
  Uses the cache module configured via `config :ex_saml, cache: MyApp.Cache`.

  The `take/1` function atomically retrieves and deletes the code,
  ensuring single-use consumption.

  Every write and exchange is traced by `ExSaml.Debug` when debug mode is on,
  so a "code not found at callback" can be diagnosed from the library side
  (already used, expired, never stored, different node). A missed `take/1` on a
  code minted by the library also promotes the flow's capture, so the
  `SAMLResponse` that led to it is kept.
  """

  alias ExSaml.Debug

  @ttl :timer.seconds(30)

  @doc "Returns the default TTL for authorization codes (30 seconds)."
  def ttl, do: @ttl

  @doc "Retrieves the authorization code data for the given key."
  def get(key), do: cache().get(cache_key(key))

  @doc "Stores authorization code data with the default TTL."
  def put(key, value, opts \\ []) do
    ttl = Keyword.get(opts, :ttl, @ttl)
    result = cache().put(cache_key(key), value, ttl: ttl)
    trace(:code_stored, key, %{value: value, ttl: ttl, result: result})
    result
  end

  @doc "Atomically retrieves and deletes the authorization code (single-use)."
  def take(key) do
    ck = cache_key(key)
    ctx = code_context(key)
    remaining_ttl = if Debug.enabled?(ctx.idp_id), do: safe_ttl(ck)
    value = cache().take(ck)

    trace(:code_taken, key, ctx, %{
      hit: not is_nil(value),
      value: value,
      remaining_ttl: remaining_ttl
    })

    if is_nil(value) do
      Debug.promote(
        ctx.trace_id,
        %{reason: :authorization_code_not_found, step: :code_exchange, idp_id: ctx.idp_id},
        :authorization_code_not_found
      )
    end

    value
  end

  @doc "Stores only if the key doesn't already exist. Returns `:ok` or `{:error, :already_exists}`."
  def put_new!(key, value, opts \\ []) do
    ttl = Keyword.get(opts, :ttl, @ttl)

    ck = cache_key(key)

    result = cache().put_new!(ck, value, ttl: ttl)
    trace(:code_stored, key, %{value: value, ttl: ttl, result: result, put_new: true})
    result
  end

  defp trace(event, code, meta), do: trace(event, code, code_context(code), meta)

  defp trace(event, code, ctx, meta) do
    Debug.log(
      event,
      meta
      |> Map.put(:code, code)
      |> Map.put(:trace_id, ctx.trace_id)
      |> Map.put(:idp_id, ctx.idp_id)
    )
  end

  # Codes minted by `ExSaml.SPHandler` in debug mode are linked to their flow
  # (`trace_id` + `idp_id`), which lets per-IdP debug apply on the exchange
  # side even though that request carries no process context. Codes minted by
  # consumers are not linked and are only traced under the global flag.
  defp code_context(code) do
    case Debug.code_context(code) do
      %{trace_id: trace_id, idp_id: idp_id} -> %{trace_id: trace_id, idp_id: idp_id}
      _ -> %{trace_id: nil, idp_id: nil}
    end
  end

  defp safe_ttl(ck) do
    cache().ttl(ck)
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  defp cache, do: Application.get_env(:ex_saml, :cache)

  defp cache_key(key), do: {__MODULE__, key}
end
