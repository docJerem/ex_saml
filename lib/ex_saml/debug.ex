defmodule ExSaml.Debug do
  @moduledoc """
  Runtime debug mode for the SSO flow.

  When enabled, the library traces every decision point of the sign-in flow
  (AuthnRequest, IdP response, decoding, validation, code issuance and
  redemption), accumulates the same data in a per-flow *report* stored in the
  cache, and can *capture* the raw `SAMLResponse` for later replay.

  ## Enabling at runtime

  The flag lives in the cache configured via `config :ex_saml, cache:` (or
  `config :ex_saml, debug_cache:` to keep debug data out of the main cache), so
  it can be turned on **without a redeploy, a restart or a config change**, from
  a remote console or a one-off rpc, and it is immediately visible to every node
  sharing the cache:

      # bin/my_app remote
      iex> ExSaml.Debug.enable(ttl: :timer.minutes(30))
      iex> ExSaml.Debug.enable(idp_id: "acme", ttl: :timer.minutes(30), capture: :always, log: :silent)
      iex> ExSaml.Debug.status()
      iex> ExSaml.Debug.disable("acme")

  Scope is either global or a single `idp_id`, and the flag **always expires**
  (default 1 hour). Defaults to `false`.

  ## Options

    * `capture:` — when to store the raw `SAMLResponse` (`saml_response/1`):
      `:on_error` (default), `:always` or `:none`. Captures live under their own
      TTL (`config :ex_saml, payload_ttl:`, default 1 hour).
    * `log:` — what goes to `Logger` at `:warning` (level configurable with
      `config :ex_saml, debug_log_level:`): `:steps` (default) logs every step
      but **redacts** the payload, the assertion and the NameID from the log
      message (they stay in the report); `:full` logs everything; `:silent`
      logs nothing and only feeds the report and the capture.

  `config :ex_saml, debug: true` (or a keyword list of the options above) is a
  static override meant for dev/test. When no cache is configured, `enable/1`
  falls back to a node-local toggle with the same TTL semantics.

  ## Warning: PII

  The report and the capture hold the raw `SAMLResponse`, the NameID and the
  assertion attributes in the cache; `log: :full` also writes them to the logs.
  Keep the TTL short, scope to a single `idp_id`, and consider a dedicated
  `debug_cache:` in production.

  ## Reports and captures

  Every step is appended to a report keyed by a `debug_id` (the `relay_state`
  for SP-initiated flows). On failure, `%ExSaml.Error{id: _}` is linked to that
  flow, so `report/1` and `saml_response/1` accept the error id — the only
  identifier a consumer needs to keep.
  """

  require Logger

  @default_ttl :timer.hours(1)
  @default_report_ttl :timer.minutes(15)
  @default_payload_ttl :timer.hours(1)
  @default_log_level :warning
  @runtime_env :debug_runtime
  @stash_key :ex_saml_debug_payload

  @capture_modes [:none, :on_error, :always]
  @log_modes [:steps, :full, :silent]
  @defaults %{capture: :on_error, log: :steps}

  # Keys stripped from the log message in `log: :steps` mode (kept in the report).
  @pii_keys [
    :saml_response,
    :saml_request,
    :assertion,
    :attributes,
    :assertion_key,
    :value,
    :relay_cache_entry,
    :cache_value
  ]

  @type scope :: :global | {:idp, binary()}
  @type step :: atom()
  @type report :: [{step(), map()}]
  @type settings :: %{capture: :none | :on_error | :always, log: :steps | :full | :silent}

  # ---------------------------------------------------------------------------
  # Activation
  # ---------------------------------------------------------------------------

  @doc """
  Enables debug mode at runtime.

  Options:

    * `:idp_id` — restrict to one IdP (default: global)
    * `:ttl` — milliseconds before the flag expires (default: 1 hour)
    * `:capture` — `:on_error` (default), `:always` or `:none`
    * `:log` — `:steps` (default), `:full` or `:silent`
  """
  @spec enable(keyword()) ::
          {:ok, %{scope: scope(), expires_at: DateTime.t(), settings: settings()}}
  def enable(opts \\ []) do
    scope = scope(Keyword.get(opts, :idp_id))
    ttl = Keyword.get(opts, :ttl, @default_ttl)
    settings = settings_from(opts)
    expires_at = DateTime.add(DateTime.utc_now(), ttl, :millisecond)

    case debug_cache() do
      nil -> runtime_put(scope, {settings, expires_at})
      cache -> cache.put(flag_key(scope), settings, ttl: ttl)
    end

    {:ok, %{scope: scope, expires_at: expires_at, settings: settings}}
  end

  @doc "Disables debug mode for the given scope (global when `idp_id` is nil)."
  @spec disable(binary() | nil) :: :ok
  def disable(idp_id \\ nil) do
    scope = scope(idp_id)
    runtime_delete(scope)
    if cache = debug_cache(), do: cache.delete(flag_key(scope))
    :ok
  end

  @doc """
  Returns the current activation state: the global flag, the IdPs with a
  dedicated flag, their settings, and the remaining TTL (ms) per scope.
  """
  @spec status() :: map()
  def status do
    cache_scopes =
      case debug_cache() do
        nil ->
          []

        cache ->
          cache.all(nil, return: :key)
          |> Enum.filter(&match?({__MODULE__, {:idp, _}}, &1))
          |> Enum.map(fn {_, scope} -> scope end)
      end

    runtime_scopes =
      runtime_map()
      |> Enum.reject(fn {_scope, {_settings, expires_at}} -> expired?(expires_at) end)
      |> Enum.map(fn {scope, _} -> scope end)
      |> Enum.filter(&match?({:idp, _}, &1))

    scopes = Enum.uniq(cache_scopes ++ runtime_scopes)

    %{
      global: enabled?(),
      static: static_enabled?(),
      idps: Enum.map(scopes, fn {:idp, id} -> id end),
      settings: Map.new([:global | scopes], fn scope -> {scope, scope_settings(scope)} end),
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
  def enabled?(idp_id \\ nil), do: not is_nil(settings(idp_id))

  @doc """
  The effective settings for the IdP (the IdP-specific flag wins over the
  global one), or `nil` when debug is off. Never raises.
  """
  @spec settings(binary() | nil) :: settings() | nil
  def settings(idp_id \\ nil) do
    static_settings() || runtime_settings(idp_id) || cache_settings(idp_id)
  rescue
    _ -> nil
  catch
    _, _ -> nil
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

    case settings(idp_id) do
      nil ->
        :ok

      %{log: log_mode} ->
        meta = if is_function(meta, 0), do: meta.(), else: meta
        idp_id = Map.get(meta, :idp_id) || idp_id
        debug_id = Map.get(meta, :debug_id) || ctx_debug_id

        entry =
          meta
          |> Map.put(:idp_id, idp_id)
          |> Map.put(:debug_id, debug_id)
          |> Map.put(:node, node())
          |> Map.put(:at, DateTime.utc_now())

        write_log(log_mode, step, entry)
        if debug_id, do: capture(debug_id, step, entry)
        :ok
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp write_log(:silent, _step, _entry), do: :ok

  defp write_log(mode, step, entry) do
    entry = if mode == :steps, do: redact(entry), else: entry
    Logger.log(log_level(), "[ExSaml.Debug] #{step} #{inspect(entry, inspect_opts())}")
  end

  defp redact(entry) do
    Enum.reduce(@pii_keys, entry, fn key, acc ->
      if Map.has_key?(acc, key) and not is_nil(acc[key]),
        do: Map.put(acc, key, :redacted),
        else: acc
    end)
  end

  @doc "Appends `{step, meta}` to the report identified by `debug_id`."
  @spec capture(binary(), step(), map()) :: :ok
  def capture(debug_id, step, meta) when is_binary(debug_id) and debug_id != "" do
    case debug_cache() do
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

  @doc """
  Returns the ordered list of `{step, meta}` captured for a flow, or `nil`.
  Accepts a `debug_id` or an `%ExSaml.Error{}` id.
  """
  @spec report(binary() | nil) :: report() | nil
  def report(nil), do: nil

  def report(id) do
    if cache = debug_cache(), do: cache.get(report_key(resolve(id)))
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  # ---------------------------------------------------------------------------
  # SAMLResponse capture
  # ---------------------------------------------------------------------------

  @doc """
  Records the raw IdP payload for the current request. With `capture: :always`
  it is stored right away; with `:on_error` it is kept in the process until
  `persist_payload/1` is called from the failure path. Never raises.
  """
  @spec stash_payload(binary() | nil, binary() | nil, map()) :: :ok
  def stash_payload(idp_id, debug_id, payload) when is_map(payload) do
    case settings(idp_id) do
      %{capture: :always} ->
        persist(debug_id, Map.put(payload, :captured_on, :always))

      %{capture: :on_error} ->
        Process.put(@stash_key, {debug_id, payload})
        :ok

      _ ->
        :ok
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc "Stores the payload stashed by `stash_payload/3`, if any, under `debug_id`."
  @spec persist_payload(binary() | nil) :: :ok
  def persist_payload(debug_id) do
    case Process.delete(@stash_key) do
      {stashed_id, payload} ->
        persist(debug_id || stashed_id, Map.put(payload, :captured_on, :error))

      _ ->
        :ok
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc """
  Returns the captured IdP payload for a flow, or `nil`. Accepts a `debug_id` or
  an `%ExSaml.Error{}` id. The map holds the raw base64 `saml_response`, the
  decoded `xml`, `saml_encoding`, `relay_state`, `idp_id`, `host`,
  `received_at` and `captured_on` (`:always` or `:error`).
  """
  @spec saml_response(binary() | nil) :: map() | nil
  def saml_response(nil), do: nil

  def saml_response(id) do
    if cache = debug_cache(), do: cache.get(payload_key(resolve(id)))
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  defp persist(nil, _payload), do: :ok

  defp persist(debug_id, payload) do
    if cache = debug_cache(), do: cache.put(payload_key(debug_id), payload, ttl: payload_ttl())
    :ok
  end

  # ---------------------------------------------------------------------------
  # Correlation indexes
  # ---------------------------------------------------------------------------

  @doc """
  Links an authorization code to its flow so that later cache operations on
  that code (`take/1`, `get_from_code/1`) can find the report and the IdP scope
  without any process context.
  """
  @spec link_code(term(), binary() | nil, binary() | nil) :: :ok
  def link_code(_code, nil, _idp_id), do: :ok

  def link_code(code, debug_id, idp_id) do
    if cache = debug_cache(),
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
    if cache = debug_cache(), do: cache.get(code_key(code))
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  @doc "Links an `%ExSaml.Error{}` id to its flow so `report/1` and `saml_response/1` accept it."
  @spec link_error(binary(), binary() | nil) :: :ok
  def link_error(_error_id, nil), do: :ok

  def link_error(error_id, debug_id) do
    if cache = debug_cache(),
      do: cache.put(error_key(error_id), debug_id, ttl: max(report_ttl(), payload_ttl()))

    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  # An error id resolves to its flow's debug_id; anything else is used as is.
  defp resolve(id) do
    case debug_cache() do
      nil ->
        id

      cache ->
        case cache.get(error_key(id)) do
          debug_id when is_binary(debug_id) -> debug_id
          _ -> id
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Internals
  # ---------------------------------------------------------------------------

  defp scope(nil), do: :global
  defp scope(idp_id), do: {:idp, idp_id}

  defp flag_key(scope), do: {__MODULE__, scope}
  defp report_key(debug_id), do: {__MODULE__, {:report, debug_id}}
  defp payload_key(debug_id), do: {__MODULE__, {:payload, debug_id}}
  defp code_key(code), do: {__MODULE__, {:code, code}}
  defp error_key(error_id), do: {__MODULE__, {:error, error_id}}

  defp debug_cache,
    do: Application.get_env(:ex_saml, :debug_cache) || Application.get_env(:ex_saml, :cache)

  defp report_ttl, do: Application.get_env(:ex_saml, :debug_report_ttl, @default_report_ttl)
  defp payload_ttl, do: Application.get_env(:ex_saml, :payload_ttl, @default_payload_ttl)
  defp log_level, do: Application.get_env(:ex_saml, :debug_log_level, @default_log_level)

  defp settings_from(opts) do
    capture = Keyword.get(opts, :capture, @defaults.capture)
    log = Keyword.get(opts, :log, @defaults.log)

    unless capture in @capture_modes,
      do: raise(ArgumentError, "capture: must be one of #{inspect(@capture_modes)}")

    unless log in @log_modes,
      do: raise(ArgumentError, "log: must be one of #{inspect(@log_modes)}")

    %{capture: capture, log: log}
  end

  # Accepts a stored `true` (pre-settings flag) as the defaults.
  defp normalize(true), do: @defaults
  defp normalize(%{capture: _, log: _} = settings), do: settings
  defp normalize(_), do: nil

  defp static_enabled?, do: not is_nil(static_settings())

  defp static_settings do
    case Application.get_env(:ex_saml, :debug, false) do
      true -> @defaults
      opts when is_list(opts) and opts != [] -> settings_from(opts)
      _ -> nil
    end
  end

  defp cache_settings(idp_id) do
    case debug_cache() do
      nil ->
        nil

      cache ->
        idp = if is_binary(idp_id), do: normalize(cache.get(flag_key({:idp, idp_id})))
        idp || normalize(cache.get(flag_key(:global)))
    end
  end

  defp runtime_settings(idp_id) do
    map = runtime_map()
    idp = if is_binary(idp_id), do: active(map, {:idp, idp_id})
    idp || active(map, :global)
  end

  defp active(map, scope) do
    case Map.get(map, scope) do
      {settings, expires_at} -> if expired?(expires_at), do: nil, else: normalize(settings)
      _ -> nil
    end
  end

  defp scope_settings(:global), do: settings()
  defp scope_settings({:idp, id}), do: settings(id)

  defp expired?(%DateTime{} = expires_at),
    do: DateTime.compare(DateTime.utc_now(), expires_at) != :lt

  defp runtime_map, do: Application.get_env(:ex_saml, @runtime_env, %{})

  defp runtime_put(scope, value),
    do: Application.put_env(:ex_saml, @runtime_env, Map.put(runtime_map(), scope, value))

  defp runtime_delete(scope),
    do: Application.put_env(:ex_saml, @runtime_env, Map.delete(runtime_map(), scope))

  defp remaining_ttl(scope) do
    from_runtime =
      case Map.get(runtime_map(), scope) do
        {_settings, %DateTime{} = expires_at} ->
          max(DateTime.diff(expires_at, DateTime.utc_now(), :millisecond), 0)

        _ ->
          nil
      end

    from_cache =
      case debug_cache() do
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
