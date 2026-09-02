defmodule ExSaml.Debug do
  @moduledoc """
  Runtime debug mode for the SSO flow: traces, captures and replay.

  Every sign-in flow has a **`trace_id`** (the `RelayState` for SP-initiated
  flows, a fresh id otherwise). It exists whether debug is on or off: it is the
  identifier of `%ExSaml.Error{}`, it travels in the authorization code payload,
  and it is the key of everything this module records. When debug is enabled,
  the library:

    * records a **trace** — the ordered events of the flow (AuthnRequest, IdP
      response, decoding, validation, code issuance and exchange) — readable
      with `trace/1`;
    * keeps a **capture** of the failed flow — a summary of the error plus the
      raw `SAMLResponse` — readable with `failure/1`, listed per IdP with
      `failures/1`, replayable with `replay/2`;
    * logs each event (`log:` option).

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
      iex> ExSaml.Debug.failures("acme")
      iex> ExSaml.Debug.disable("acme")

  Scope is either global or a single `idp_id` (the IdP flag wins), and the flag
  **always expires** (default 1 hour). Defaults to `false`.

  ## Options

    * `capture:` — when to keep the raw `SAMLResponse`: `:on_error` (default),
      `:always` or `:none`. With `:on_error` the payload is written at receipt
      with a short TTL (`provisional_ttl`, default 2 min) and **promoted**
      (`payload_ttl`, default 1 h, indexed per IdP) when the flow fails — in the
      library, or later when the authorization code cannot be exchanged. With
      `:none` a failure still leaves a capture, without the payload.
    * `log:` — what goes to `Logger` (level `debug_log_level`, default
      `:warning`): `:steps` (default) logs every event but **redacts** the
      payload, the assertion and the NameID from the message (they stay in the
      trace); `:full` logs everything; `:silent` logs nothing.

  `config :ex_saml, debug: true` (or a keyword list of the options above) is a
  static override meant for dev/test. When no cache is configured, `enable/1`
  falls back to a node-local toggle with the same TTL semantics.

  ## Warning: PII

  Traces and captures hold the raw `SAMLResponse`, the NameID and the assertion
  attributes in the cache; `log: :full` also writes them to the logs. Keep the
  TTL short, scope to a single `idp_id`, and consider a dedicated
  `debug_cache:` in production. At most `max_failures_per_idp` (default 20)
  captures are kept per IdP.
  """

  require Logger

  alias ExSaml.{Error, Helper, IdpData}

  @default_ttl :timer.hours(1)
  @default_trace_ttl :timer.minutes(15)
  @default_payload_ttl :timer.hours(1)
  @default_provisional_ttl :timer.minutes(2)
  @default_max_failures 20
  @default_log_level :warning
  @runtime_env :debug_runtime
  @stash_key :ex_saml_debug_capture

  @capture_modes [:none, :on_error, :always]
  @log_modes [:steps, :full, :silent]
  @defaults %{capture: :on_error, log: :steps}

  # Keys stripped from the log message in `log: :steps` mode (kept in the trace).
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
  @type event :: atom()
  @type trace :: [{event(), map()}]
  @type settings :: %{capture: :none | :on_error | :always, log: :steps | :full | :silent}
  @type capture :: %{
          trace_id: binary(),
          idp_id: binary() | nil,
          received_at: DateTime.t() | nil,
          captured_on:
            :pending | :always | :error | :authorization_code_not_found | :assertion_not_found,
          error: map() | nil,
          saml_response: binary() | nil,
          saml_encoding: binary() | nil,
          relay_state: binary() | nil,
          consume_uri: binary() | nil,
          entity_id: binary() | nil
        }

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
  Stores the IdP id and the trace id in the process `Logger` metadata so that
  modules without access to the conn (`ExSaml.Core.*`, caches) can still log
  under the right scope and trace.
  """
  @spec put_context(binary() | nil, binary() | nil) :: :ok
  def put_context(idp_id, trace_id) do
    Logger.metadata(ex_saml_idp_id: idp_id, ex_saml_trace_id: trace_id)
  end

  @doc "Returns `{idp_id, trace_id}` from the process context (either may be nil)."
  @spec context() :: {binary() | nil, binary() | nil}
  def context do
    md = Logger.metadata()
    {md[:ex_saml_idp_id], md[:ex_saml_trace_id]}
  end

  # ---------------------------------------------------------------------------
  # Events and traces
  # ---------------------------------------------------------------------------

  @doc """
  Logs an event with its metadata and appends it to the flow trace, when debug
  is enabled for the IdP found in `meta[:idp_id]` or in the process context.

  `meta` may be a map or a zero-arity function returning a map, so that
  expensive metadata is only built when debug is on. Never raises.
  """
  @spec log(event(), map() | (-> map())) :: :ok
  def log(event, meta) when is_map(meta) or is_function(meta, 0) do
    peek = if is_map(meta), do: meta, else: %{}
    log(event, Map.get(peek, :idp_id), meta)
  end

  @doc """
  Same as `log/2` with an explicit `idp_id` used for the scope check, so lazy
  metadata can be used without a process context.
  """
  @spec log(event(), binary() | nil, map() | (-> map())) :: :ok
  def log(event, idp_id, meta) when is_map(meta) or is_function(meta, 0) do
    {ctx_idp, ctx_trace_id} = context()
    idp_id = idp_id || ctx_idp

    case settings(idp_id) do
      nil ->
        :ok

      %{log: log_mode} ->
        meta = if is_function(meta, 0), do: meta.(), else: meta
        idp_id = Map.get(meta, :idp_id) || idp_id
        trace_id = Map.get(meta, :trace_id) || ctx_trace_id

        entry =
          meta
          |> Map.put(:idp_id, idp_id)
          |> Map.put(:trace_id, trace_id)
          |> Map.put(:node, node())
          |> Map.put(:at, DateTime.utc_now())

        write_log(log_mode, event, entry)
        if trace_id, do: record(trace_id, event, entry)
        :ok
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp write_log(:silent, _event, _entry), do: :ok

  defp write_log(mode, event, entry) do
    entry = if mode == :steps, do: redact(entry), else: entry
    Logger.log(log_level(), "[ExSaml.Debug] #{event} #{inspect(entry, inspect_opts())}")
  end

  defp redact(entry) do
    Enum.reduce(@pii_keys, entry, fn key, acc ->
      if Map.has_key?(acc, key) and not is_nil(acc[key]),
        do: Map.put(acc, key, :redacted),
        else: acc
    end)
  end

  @doc "Appends `{event, meta}` to the trace identified by `trace_id`."
  @spec record(binary(), event(), map()) :: :ok
  def record(trace_id, event, meta) when is_binary(trace_id) and trace_id != "" do
    case debug_cache() do
      nil ->
        :ok

      cache ->
        key = trace_key(trace_id)
        trace = cache.get(key) || []
        cache.put(key, trace ++ [{event, meta}], ttl: trace_ttl())
        :ok
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  def record(_, _, _), do: :ok

  @doc "Returns the ordered list of `{event, meta}` recorded for a flow, or `nil`."
  @spec trace(binary() | nil) :: trace() | nil
  def trace(nil), do: nil

  def trace(trace_id) do
    if cache = debug_cache(), do: cache.get(trace_key(trace_id))
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  # ---------------------------------------------------------------------------
  # Captures
  # ---------------------------------------------------------------------------

  @doc """
  Records the IdP payload received for the flow, according to the `capture:`
  setting: written with a short provisional TTL (`:on_error`), with the full
  `payload_ttl` (`:always`), or kept without the payload (`:none`). The
  capture is later completed by `promote/3` when the flow fails. Never raises.
  """
  @spec stash_capture(binary() | nil, binary() | nil, map()) :: :ok
  def stash_capture(idp_id, trace_id, payload) when is_map(payload) do
    case settings(idp_id) do
      nil ->
        :ok

      %{capture: mode} ->
        capture =
          payload
          |> Map.take([:saml_response, :saml_encoding, :relay_state, :consume_uri, :entity_id])
          |> Map.merge(%{
            trace_id: trace_id,
            idp_id: idp_id,
            received_at: Map.get(payload, :received_at, DateTime.utc_now()),
            captured_on: :pending,
            error: nil
          })

        capture = if mode == :none, do: %{capture | saml_response: nil}, else: capture
        Process.put(@stash_key, capture)

        case mode do
          :always -> write_capture(%{capture | captured_on: :always}, payload_ttl())
          :on_error -> write_capture(capture, provisional_ttl())
          :none -> :ok
        end
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc """
  Marks the flow as failed: completes the capture with the error summary, gives
  it the full `payload_ttl` and adds it to the IdP's failure list.

  `error` is an `%ExSaml.Error{}` or a map with `reason`, `scope`, `step`.
  Never raises.
  """
  @spec promote(binary() | nil, Error.t() | map(), atom()) :: :ok
  def promote(trace_id, error, captured_on \\ :error)

  def promote(nil, _error, _captured_on), do: :ok

  def promote(trace_id, error, captured_on) do
    summary = error_summary(error, trace_id)
    stashed = Process.get(@stash_key)

    existing =
      read_capture(trace_id) ||
        (stashed && stashed.trace_id == trace_id && stashed) ||
        %{trace_id: trace_id, idp_id: summary[:idp_id], received_at: nil, saml_response: nil}

    idp_id = existing[:idp_id] || summary[:idp_id]

    case settings(idp_id) do
      nil -> :ok
      %{capture: mode} -> finish_promotion(existing, mode, summary, idp_id, captured_on)
    end
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp finish_promotion(existing, mode, summary, idp_id, captured_on) do
    capture = Map.merge(existing, %{captured_on: captured_on, error: summary, idp_id: idp_id})
    capture = if mode == :none, do: %{capture | saml_response: nil}, else: capture

    write_capture(capture, payload_ttl())
    index_failure(idp_id, capture.trace_id)
    :ok
  end

  @doc "Returns the capture of a flow (pending or failed), or `nil`."
  @spec capture(binary() | nil) :: capture() | nil
  def capture(nil), do: nil

  def capture(trace_id) do
    read_capture(trace_id)
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  @doc "Returns the capture of a **failed** flow (error summary + payload), or `nil`."
  @spec failure(binary() | nil) :: capture() | nil
  def failure(trace_id) do
    case capture(trace_id) do
      %{error: %{}} = capture -> capture
      _ -> nil
    end
  end

  @doc """
  Lists the failed flows of an IdP, most recent first, as summaries:
  `%{trace_id, received_at, captured_on, error}`. At most
  `max_failures_per_idp` are kept.
  """
  @spec failures(binary()) :: [map()]
  def failures(idp_id) do
    case debug_cache() do
      nil ->
        []

      cache ->
        (cache.get(failures_key(idp_id)) || [])
        |> Enum.map(&read_capture/1)
        |> Enum.reject(&is_nil/1)
        |> Enum.map(&Map.take(&1, [:trace_id, :received_at, :captured_on, :error]))
    end
  rescue
    _ -> []
  catch
    _, _ -> []
  end

  @doc """
  Returns the captured `SAMLResponse` of a flow, or `nil`. Pass `decode: true`
  to get the XML document instead of the base64 exactly as posted by the IdP.
  """
  @spec saml_response(binary() | nil, keyword()) :: binary() | nil
  def saml_response(trace_id, opts \\ []) do
    case capture(trace_id) do
      %{saml_response: payload} when is_binary(payload) ->
        if Keyword.get(opts, :decode, false),
          do: decode_payload(Map.get(capture(trace_id), :saml_encoding), payload),
          else: payload

      _ ->
        nil
    end
  end

  # ---------------------------------------------------------------------------
  # Replay
  # ---------------------------------------------------------------------------

  @doc """
  Replays the captured `SAMLResponse` of a failed flow against the **current**
  configuration of its IdP, evaluated at the instant the response was received
  (`now: received_at`, so time conditions behave as they did) — or at any
  instant given with `now:`.

  Returns `{:ok, %ExSaml.Core.Assertion{}}` when the response now validates, or
  `{:error, %ExSaml.Error{}}` with the same vocabulary as the live flow.
  Signatures are checked against the current IdP metadata: a rotated
  certificate shows up as `:cert_not_accepted`.
  """
  @spec replay(binary(), keyword()) :: {:ok, ExSaml.Core.Assertion.t()} | {:error, Error.t()}
  def replay(trace_id, opts \\ []) do
    with %{} = capture <- capture(trace_id) || {:error, :capture_not_found},
         payload when is_binary(payload) <-
           capture.saml_response || {:error, :payload_not_captured},
         %IdpData{sp_config: sp_cfg} <-
           Helper.get_idp(capture.idp_id) || {:error, {:unknown_idp, capture.idp_id}} do
      sp = %{
        sp_cfg
        | consume_uri: capture[:consume_uri] || sp_cfg.consume_uri,
          entity_id: capture[:entity_id] || sp_cfg.entity_id
      }

      now = Keyword.get(opts, :now, capture.received_at)
      put_context(capture.idp_id, nil)

      case Helper.decode_idp_auth_resp(sp, capture.saml_encoding, payload, now: now) do
        {:ok, assertion} ->
          {:ok, assertion}

        {:error, reason} ->
          {:error, Error.from_reason(reason, replay_attrs(capture))}
      end
    else
      {:error, reason} ->
        {:error, Error.from_reason(reason, %{trace_id: trace_id, step: :replay})}
    end
  end

  defp replay_attrs(capture) do
    %{
      trace_id: capture.trace_id,
      idp_id: capture.idp_id,
      relay_state: capture[:relay_state],
      step: :decode
    }
  end

  # ---------------------------------------------------------------------------
  # Code correlation
  # ---------------------------------------------------------------------------

  @doc """
  Links an authorization code to its flow so that later cache operations on
  that code (`take/1`, `get_from_code/1`) can find the trace and the IdP scope
  without any process context.
  """
  @spec link_code(term(), binary() | nil, binary() | nil) :: :ok
  def link_code(_code, nil, _idp_id), do: :ok

  def link_code(code, trace_id, idp_id) do
    if cache = debug_cache(),
      do: cache.put(code_key(code), %{trace_id: trace_id, idp_id: idp_id}, ttl: trace_ttl())

    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc "Returns `%{trace_id: _, idp_id: _}` linked to the code, or `nil`."
  @spec code_context(term()) :: %{trace_id: binary(), idp_id: binary() | nil} | nil
  def code_context(code) do
    if cache = debug_cache(), do: cache.get(code_key(code))
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
  defp trace_key(trace_id), do: {__MODULE__, {:trace, trace_id}}
  defp capture_key(trace_id), do: {__MODULE__, {:capture, trace_id}}
  defp failures_key(idp_id), do: {__MODULE__, {:failures, idp_id}}
  defp code_key(code), do: {__MODULE__, {:code, code}}

  defp read_capture(trace_id) when is_binary(trace_id) do
    if cache = debug_cache(), do: cache.get(capture_key(trace_id))
  end

  defp read_capture(_), do: nil

  defp write_capture(%{trace_id: trace_id} = capture, ttl) when is_binary(trace_id) do
    if cache = debug_cache(), do: cache.put(capture_key(trace_id), capture, ttl: ttl)
    :ok
  end

  defp write_capture(_, _), do: :ok

  # Newest first, bounded; evicted captures are deleted.
  defp index_failure(nil, _trace_id), do: :ok

  defp index_failure(idp_id, trace_id) do
    if cache = debug_cache() do
      key = failures_key(idp_id)
      current = (cache.get(key) || []) |> List.delete(trace_id)
      {kept, evicted} = Enum.split([trace_id | current], max_failures())
      Enum.each(evicted, &cache.delete(capture_key(&1)))
      cache.put(key, kept, ttl: payload_ttl())
    end

    :ok
  end

  defp error_summary(%Error{} = e, _trace_id),
    do: %{trace_id: e.trace_id, reason: e.reason, scope: e.scope, step: e.step, idp_id: e.idp_id}

  defp error_summary(map, trace_id) when is_map(map) do
    map
    |> Map.take([:reason, :scope, :step, :idp_id])
    |> Map.put(:trace_id, trace_id)
    |> Map.put_new(:scope, nil)
  end

  defp decode_payload(encoding, payload) do
    decoded =
      if encoding == IdpData.oasis_redirect_flow_uri(),
        do: payload |> :base64.decode() |> :zlib.unzip(),
        else: :base64.decode(payload)

    if String.valid?(decoded), do: decoded, else: nil
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end

  defp debug_cache,
    do: Application.get_env(:ex_saml, :debug_cache) || Application.get_env(:ex_saml, :cache)

  defp trace_ttl, do: Application.get_env(:ex_saml, :trace_ttl, @default_trace_ttl)
  defp payload_ttl, do: Application.get_env(:ex_saml, :payload_ttl, @default_payload_ttl)

  defp provisional_ttl,
    do: Application.get_env(:ex_saml, :provisional_ttl, @default_provisional_ttl)

  defp max_failures,
    do: Application.get_env(:ex_saml, :max_failures_per_idp, @default_max_failures)

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
