defmodule ExSaml.Debug do
  @moduledoc """
  Runtime debug mode for the SSO flow.

  When enabled, the library logs every decision point of the sign-in flow
  (AuthnRequest, IdP response, decoding, validation, code issuance and
  redemption) at `:warning` level with the full context in the message body,
  and accumulates the same data in a per-flow *report* stored in the cache
  configured via `config :ex_saml, cache: MyApp.Cache`.

  ## Enabling at runtime

  The flag itself lives in that cache, so it can be turned on **without a
  redeploy, a restart or a config change**, from a remote console or a one-off
  rpc, and it is immediately visible to every node sharing the cache:

      # bin/my_app remote
      iex> ExSaml.Debug.enable(ttl: :timer.minutes(30))
      iex> ExSaml.Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))
      iex> ExSaml.Debug.status()
      iex> ExSaml.Debug.disable()

  Scope is either global or a single `idp_id`, and the flag **always expires**
  (default 1 hour). Defaults to `false`.

  `config :ex_saml, debug: true` is a static override meant for dev/test. When
  no cache is configured, `enable/1` falls back to a node-local toggle with the
  same TTL semantics.

  ## Warning: PII

  In debug mode the raw `SAMLResponse`, the NameID and the assertion attributes
  are written to the logs and to the report. Keep the TTL short and scope to a
  single `idp_id` whenever possible.

  ## Reports

  Every step is appended to a report keyed by a `debug_id` (the `relay_state`
  for SP-initiated flows). The `debug_id` travels in the authorization code
  payload on success and in `%ExSaml.Error{}` on failure, so a consumer can read
  the whole flow with `report/1`.
  """

  require Logger

  @default_ttl :timer.hours(1)
  @default_report_ttl :timer.minutes(15)
  @runtime_env :debug_runtime

  @type scope :: :global | {:idp, binary()}
  @type step :: atom()
  @type report :: [{step(), map()}]

  # ---------------------------------------------------------------------------
  # Activation
  # ---------------------------------------------------------------------------

  @doc """
  Enables debug mode at runtime.

  Options:

    * `:idp_id` — restrict to one IdP (default: global)
    * `:ttl` — milliseconds before the flag expires (default: 1 hour)

  Writes the flag in the configured cache (visible cluster-wide), or falls back
  to a node-local toggle when no cache is configured.
  """
  @spec enable(keyword()) :: {:ok, %{scope: scope(), expires_at: DateTime.t()}}
  def enable(opts \\ []) do
    scope = scope(Keyword.get(opts, :idp_id))
    ttl = Keyword.get(opts, :ttl, @default_ttl)
    expires_at = DateTime.add(DateTime.utc_now(), ttl, :millisecond)

    case cache() do
      nil -> runtime_put(scope, expires_at)
      cache -> cache.put(flag_key(scope), true, ttl: ttl)
    end

    {:ok, %{scope: scope, expires_at: expires_at}}
  end

  @doc "Disables debug mode for the given scope (global when `idp_id` is nil)."
  @spec disable(binary() | nil) :: :ok
  def disable(idp_id \\ nil) do
    scope = scope(idp_id)
    runtime_delete(scope)
    if cache = cache(), do: cache.delete(flag_key(scope))
    :ok
  end

  @doc """
  Returns the current activation state: the global flag, the list of IdPs with
  a dedicated flag, and the remaining TTL (ms) per scope when known.
  """
  @spec status() :: map()
  def status do
    idp_scopes =
      case cache() do
        nil ->
          []

        cache ->
          cache.all(nil, return: :key)
          |> Enum.filter(&match?({__MODULE__, {:idp, _}}, &1))
          |> Enum.map(fn {_, scope} -> scope end)
      end

    runtime_scopes =
      runtime_map()
      |> Enum.filter(fn {_scope, expires_at} -> not expired?(expires_at) end)
      |> Enum.map(fn {scope, _} -> scope end)

    scopes = Enum.uniq(idp_scopes ++ Enum.filter(runtime_scopes, &match?({:idp, _}, &1)))

    %{
      global: enabled?(),
      static: static_enabled?(),
      idps: Enum.map(scopes, fn {:idp, id} -> id end),
      expires_in_ms:
        [:global | scopes]
        |> Enum.map(fn scope -> {scope, remaining_ttl(scope)} end)
        |> Enum.reject(fn {_, ttl} -> is_nil(ttl) end)
        |> Map.new()
    }
  rescue
    error -> %{global: false, static: static_enabled?(), idps: [], error: inspect(error)}
  end

  @doc """
  Whether debug mode is active, globally or for the given `idp_id`.

  Never raises: any cache failure yields `false` so the auth flow is never
  impacted by the debug machinery.
  """
  @spec enabled?(binary() | nil) :: boolean()
  def enabled?(idp_id \\ nil) do
    static_enabled?() or runtime_enabled?(idp_id) or cache_enabled?(idp_id)
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  # ---------------------------------------------------------------------------
  # Per-request context
  # ---------------------------------------------------------------------------

  @doc """
  Stores the IdP id and the debug id in the process `Logger` metadata so that
  modules without access to the conn (`ExSaml.Core.*`, caches) can still log
  under the right scope and report.
  """
  @spec put_context(binary() | nil, binary() | nil) :: :ok
  def put_context(idp_id, debug_id) do
    Logger.metadata(ex_saml_idp_id: idp_id, ex_saml_debug_id: debug_id)
  end

  @doc "Returns `{idp_id, debug_id}` from the process context (either may be nil)."
  @spec context() :: {binary() | nil, binary() | nil}
  def context do
    md = Logger.metadata()
    {md[:ex_saml_idp_id], md[:ex_saml_debug_id]}
  end

  # ---------------------------------------------------------------------------
  # Logging and reports
  # ---------------------------------------------------------------------------

  @doc """
  Logs a step with its metadata and appends it to the flow report, when debug
  is enabled for the IdP found in `meta[:idp_id]` or in the process context.

  `meta` may be a map or a zero-arity function returning a map, so that
  expensive metadata is only built when debug is on. Never raises.
  """
  @spec log(step(), map() | (-> map())) :: :ok
  def log(step, meta) when is_map(meta) or is_function(meta, 0) do
    peek = if is_map(meta), do: meta, else: %{}
    log(step, Map.get(peek, :idp_id), meta)
  end

  @doc """
  Same as `log/2` with an explicit `idp_id` used for the scope check, so lazy
  metadata can be used without a process context.
  """
  @spec log(step(), binary() | nil, map() | (-> map())) :: :ok
  def log(step, idp_id, meta) when is_map(meta) or is_function(meta, 0) do
    {ctx_idp, ctx_debug_id} = context()
    idp_id = idp_id || ctx_idp

    if enabled?(idp_id) do
      meta = if is_function(meta, 0), do: meta.(), else: meta
      idp_id = Map.get(meta, :idp_id) || idp_id
      debug_id = Map.get(meta, :debug_id) || ctx_debug_id

      entry =
        meta
        |> Map.put(:idp_id, idp_id)
        |> Map.put(:debug_id, debug_id)
        |> Map.put(:node, node())
        |> Map.put(:at, DateTime.utc_now())

      Logger.warning("[ExSaml.Debug] #{step} #{inspect(entry, inspect_opts())}")

      if debug_id, do: capture(debug_id, step, entry)
    end

    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc "Appends `{step, meta}` to the report identified by `debug_id`."
  @spec capture(binary(), step(), map()) :: :ok
  def capture(debug_id, step, meta) when is_binary(debug_id) and debug_id != "" do
    case cache() do
      nil ->
        :ok

      cache ->
        key = report_key(debug_id)
        report = cache.get(key) || []
        cache.put(key, report ++ [{step, meta}], ttl: report_ttl())
        :ok
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  def capture(_, _, _), do: :ok

  @doc "Returns the ordered list of `{step, meta}` captured for `debug_id`, or `nil`."
  @spec report(binary() | nil) :: report() | nil
  def report(nil), do: nil

  def report(debug_id) do
    if cache = cache(), do: cache.get(report_key(debug_id))
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  @doc """
  Links an authorization code to its flow so that later cache operations on
  that code (`take/1`, `get_from_code/1`) can find the report and the IdP scope
  without any process context.
  """
  @spec link_code(term(), binary() | nil, binary() | nil) :: :ok
  def link_code(_code, nil, _idp_id), do: :ok

  def link_code(code, debug_id, idp_id) do
    if cache = cache(),
      do: cache.put(code_key(code), %{debug_id: debug_id, idp_id: idp_id}, ttl: report_ttl())

    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc "Returns `%{debug_id: _, idp_id: _}` linked to the code, or `nil`."
  @spec code_context(term()) :: %{debug_id: binary(), idp_id: binary() | nil} | nil
  def code_context(code) do
    if cache = cache(), do: cache.get(code_key(code))
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  # ---------------------------------------------------------------------------
  # Internals
  # ---------------------------------------------------------------------------

  defp scope(nil), do: :global
  defp scope(idp_id), do: {:idp, idp_id}

  defp flag_key(scope), do: {__MODULE__, scope}
  defp report_key(debug_id), do: {__MODULE__, {:report, debug_id}}
  defp code_key(code), do: {__MODULE__, {:code, code}}

  defp cache, do: Application.get_env(:ex_saml, :cache)

  defp report_ttl, do: Application.get_env(:ex_saml, :debug_report_ttl, @default_report_ttl)

  defp static_enabled?, do: Application.get_env(:ex_saml, :debug, false) == true

  defp cache_enabled?(idp_id) do
    case cache() do
      nil ->
        false

      cache ->
        cache.get(flag_key(:global)) == true or
          (is_binary(idp_id) and cache.get(flag_key({:idp, idp_id})) == true)
    end
  end

  defp runtime_enabled?(idp_id) do
    map = runtime_map()

    active?(map, :global) or (is_binary(idp_id) and active?(map, {:idp, idp_id}))
  end

  defp active?(map, scope) do
    case Map.get(map, scope) do
      nil -> false
      expires_at -> not expired?(expires_at)
    end
  end

  defp expired?(%DateTime{} = expires_at),
    do: DateTime.compare(DateTime.utc_now(), expires_at) != :lt

  defp runtime_map, do: Application.get_env(:ex_saml, @runtime_env, %{})

  defp runtime_put(scope, expires_at),
    do: Application.put_env(:ex_saml, @runtime_env, Map.put(runtime_map(), scope, expires_at))

  defp runtime_delete(scope),
    do: Application.put_env(:ex_saml, @runtime_env, Map.delete(runtime_map(), scope))

  defp remaining_ttl(scope) do
    from_runtime =
      case Map.get(runtime_map(), scope) do
        %DateTime{} = expires_at ->
          max(DateTime.diff(expires_at, DateTime.utc_now(), :millisecond), 0)

        _ ->
          nil
      end

    from_cache =
      case cache() do
        nil ->
          nil

        cache ->
          case cache.ttl(flag_key(scope)) do
            ttl when is_integer(ttl) -> ttl
            _ -> nil
          end
      end

    from_cache || from_runtime
  end

  defp inspect_opts, do: [pretty: true, limit: :infinity, printable_limit: :infinity]
end
