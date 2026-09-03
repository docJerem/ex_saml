defmodule ExSaml.Debug.Access do
  @moduledoc false

  # Who may see what, and which parameters are acceptable.
  #
  # Kept out of the router so the security-relevant decisions can be tested
  # without HTTP, and so the router reads as routing.

  alias ExSaml.Debug

  @capture_modes %{"none" => :none, "on_error" => :on_error, "always" => :always}
  @log_modes %{"steps" => :steps, "full" => :full, "silent" => :silent}

  # `idp_id` reaches URLs and `trace_id` reaches a Content-Disposition filename.
  @idp_id_re ~r/\A[A-Za-z0-9._\-]{1,128}\z/
  @trace_id_re ~r/\A[A-Za-z0-9_\-]{1,128}\z/

  @known_opts [
    :authorize,
    :actor,
    :require_actor,
    :allow_global_scope,
    :allow_unredacted,
    :allow_payload_download,
    :allow_node_local,
    :max_debug_ttl_ms,
    :default_locale,
    :audit_level,
    :audit_sink
  ]

  defstruct authorize: nil,
            actor: nil,
            require_actor: true,
            allow_global_scope: false,
            allow_unredacted: false,
            allow_payload_download: true,
            allow_node_local: false,
            max_debug_ttl_ms: 4 * 60 * 60 * 1000,
            default_locale: "en",
            audit_level: :info,
            audit_sink: nil

  @type t :: %__MODULE__{}
  @type allowed :: :all | [binary()]

  @doc """
  Validates mount options at `init/1`, i.e. at compile time for both Plug's and
  Phoenix's `forward`, so a mistake fails the consumer's build rather than the
  first request.
  """
  def validate!(opts) do
    opts = normalize_opts(opts)

    case Keyword.keys(opts) -- @known_opts do
      [] -> :ok
      unknown -> raise ArgumentError, "unknown ExSaml.DebugRouter options: #{inspect(unknown)}"
    end

    # No implicit "unauthenticated by design": this router reads authentication
    # data, so the consumer states its access rule or says explicitly that it
    # has none.
    case Keyword.fetch(opts, :authorize) do
      {:ok, :none} ->
        :ok

      {:ok, {mod, fun}} when is_atom(mod) and is_atom(fun) ->
        :ok

      {:ok, fun} when is_function(fun, 1) ->
        :ok

      {:ok, other} ->
        raise ArgumentError,
              "ExSaml.DebugRouter :authorize must be {Mod, :fun}, a 1-arity function " <>
                "or :none, got: #{inspect(other)}"

      :error ->
        raise ArgumentError, """
        ExSaml.DebugRouter requires an :authorize option.

        It exposes SAML payloads and traces, so mount it with an access rule:

            forward "/", to: ExSaml.DebugRouter, init_opts: [authorize: {MyApp.Saml, :authorize}]

        Pass `authorize: :none` to state deliberately that the pipeline in front
        of it is the only control.
        """
    end

    opts
  end

  @doc "Layers mount options over the application env and the defaults."
  def build(init_opts) do
    from_env = Application.get_env(:ex_saml, :debug_api, [])

    struct(
      __MODULE__,
      from_env |> normalize_opts() |> Keyword.merge(normalize_opts(init_opts))
    )
  end

  defp normalize_opts(opts) when is_list(opts), do: opts
  defp normalize_opts(%{} = opts), do: Map.to_list(opts)
  defp normalize_opts(_opts), do: []

  @doc "Resolves the set of IdPs this caller may see."
  @spec authorize(Plug.Conn.t(), t()) :: {:ok, allowed()} | {:error, atom()}
  def authorize(_conn, %__MODULE__{authorize: :none}), do: {:ok, :all}
  def authorize(_conn, %__MODULE__{authorize: nil}), do: {:error, :forbidden}

  def authorize(conn, %__MODULE__{authorize: authorize}) do
    case call(authorize, conn) do
      {:ok, :all} -> {:ok, :all}
      {:ok, ids} when is_list(ids) -> {:ok, ids}
      {:error, :unauthenticated} -> {:error, :unauthenticated}
      _other -> {:error, :forbidden}
    end
  end

  @doc "The actor to name in the audit line."
  def actor(conn, %__MODULE__{actor: nil}), do: conn.assigns[:ex_saml_actor]

  def actor(conn, %__MODULE__{actor: actor}) do
    case call(actor, conn) do
      value when is_binary(value) -> value
      _ -> conn.assigns[:ex_saml_actor]
    end
  end

  defp call({mod, fun}, conn), do: apply(mod, fun, [conn])
  defp call(fun, conn) when is_function(fun, 1), do: fun.(conn)

  @doc "Whether an IdP is in the caller's set. A nil id never is, unless unrestricted."
  def allowed?(:all, _idp_id), do: true
  def allowed?(ids, idp_id) when is_list(ids) and is_binary(idp_id), do: idp_id in ids
  def allowed?(_ids, _idp_id), do: false

  @doc "Whether the caller may act on the global scope."
  def global_allowed?(:all, %__MODULE__{allow_global_scope: true}), do: true
  def global_allowed?(_allowed, _opts), do: false

  @doc "Identifier syntax. `trace_id` ends up in a Content-Disposition filename."
  def valid_idp_id?(id) when is_binary(id), do: Regex.match?(@idp_id_re, id)
  def valid_idp_id?(_id), do: false

  def valid_trace_id?(id) when is_binary(id), do: Regex.match?(@trace_id_re, id)
  def valid_trace_id?(_id), do: false

  @doc """
  Parses `capture` and `log` against closed catalogues.

  `Debug.enable/1` raises `ArgumentError` on an unknown mode, and turning user
  input into atoms is how an atom table fills up, so neither happens here.
  """
  def settings_opts(params) do
    with {:ok, capture} <- mode(params, "capture", @capture_modes),
         {:ok, log} <- mode(params, "log", @log_modes) do
      {:ok, Enum.reject([capture: capture, log: log], fn {_k, v} -> is_nil(v) end)}
    end
  end

  defp mode(params, key, catalogue) do
    case Map.get(params, key) do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        case Map.fetch(catalogue, value) do
          {:ok, mode} -> {:ok, mode}
          :error -> {:error, {:invalid_parameter, key, Map.keys(catalogue)}}
        end

      _other ->
        {:error, {:invalid_parameter, key, Map.keys(catalogue)}}
    end
  end

  @doc "Validates `ttl_ms` against the mount's cap."
  def ttl_ms(params, %__MODULE__{max_debug_ttl_ms: max}) do
    case Map.get(params, "ttl_ms") do
      nil -> {:ok, nil}
      ms when is_integer(ms) and ms > 0 and ms <= max -> {:ok, ms}
      ms when is_integer(ms) and ms > max -> {:error, {:ttl_too_large, max}}
      value -> parse_ttl(value, max)
    end
  end

  defp parse_ttl(value, max) when is_binary(value) do
    case Integer.parse(value) do
      {ms, ""} -> ttl_ms(%{"ttl_ms" => ms}, %__MODULE__{max_debug_ttl_ms: max})
      _ -> {:error, {:invalid_parameter, "ttl_ms", nil}}
    end
  end

  defp parse_ttl(_value, _max), do: {:error, {:invalid_parameter, "ttl_ms", nil}}

  @doc "Validates `now` on a replay request."
  def now(params) do
    case Map.get(params, "now") do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        case DateTime.from_iso8601(value) do
          {:ok, dt, _offset} -> {:ok, dt}
          _ -> {:error, {:invalid_parameter, "now", nil}}
        end

      _ ->
        {:error, {:invalid_parameter, "now", nil}}
    end
  end

  @doc "Validates `locale` against the locales the library actually ships."
  def locale(params, %__MODULE__{default_locale: default}) do
    known = Gettext.known_locales(ExSaml.Gettext)

    case Map.get(params, "locale") do
      nil -> {:ok, default}
      value when is_binary(value) -> if value in known, do: {:ok, value}, else: {:error, known}
      _ -> {:error, known}
    end
  end

  @doc """
  Resolves a capture and checks it belongs to the caller.

  A capture that is gone, unattributable or another tenant's is the same
  `:not_found`: `trace_id` values leave the system — they are the `?error_id=`
  a user pastes into a support ticket — so distinguishing them would turn a
  shareable identifier into an existence oracle. Expiry is also by far the
  likeliest case, and that is a 404 by any reading.
  """
  def scoped_capture(trace_id, allowed) do
    case Debug.capture(trace_id) do
      %{} = capture ->
        if allowed?(allowed, capture[:idp_id]), do: {:ok, capture}, else: {:error, :not_found}

      _ ->
        {:error, :not_found}
    end
  end

  @doc """
  Resolves a trace and checks it belongs to the caller.

  A trace has no owner of its own, so it is attributed by the first event that
  names an IdP — every event carries one when the flow reached IdP lookup.
  """
  def scoped_trace(trace_id, allowed) do
    with events when is_list(events) <- Debug.trace(trace_id),
         idp_id when is_binary(idp_id) <-
           Enum.find_value(events, fn {_event, meta} -> Map.get(meta, :idp_id) end),
         true <- allowed?(allowed, idp_id) do
      {:ok, events}
    else
      _ -> {:error, :not_found}
    end
  end
end
