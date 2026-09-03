defmodule ExSaml.DebugRouter do
  @moduledoc """
  A read-mostly HTTP surface over `ExSaml.Debug`, for diagnosing a failed
  sign-in without a remote console.

  Mount it behind your own admin pipeline:

      # Phoenix
      scope "/admin/saml" do
        pipe_through [:api, :require_admin]

        forward "/", ExSaml.DebugRouter,
          authorize: {MyApp.Saml.Debug, :authorize},
          actor: {MyApp.Saml.Debug, :actor}
      end

      # Plain Plug
      forward "/admin/saml",
        to: ExSaml.DebugRouter,
        init_opts: [authorize: {MyApp.Saml.Debug, :authorize}]

  ## Routes

      GET    /debug                              activation state and retention config
      PUT    /debug                              enable globally
      DELETE /debug                              disable globally
      PUT    /debug/idps/:idp_id                 enable for one IdP
      DELETE /debug/idps/:idp_id                 disable for one IdP
      GET    /idps/:idp_id/failures              recent failures, most recent first
      GET    /failures/:trace_id                 one capture, without the payload
      GET    /failures/:trace_id/saml_response   the payload, as base64 or XML
      POST   /failures/:trace_id/replay          re-run it against the live config
      GET    /traces/:trace_id                   the flow's events
      GET    /validation                         the response-validation policy

  ## Access

  This router does no authentication. It reads authentication data, so it
  refuses to start without an explicit `:authorize` decision.

    * `:authorize` — required. `{Mod, :fun}` (or a 1-arity function, or `:none`)
      called with the conn, returning `{:ok, :all}`, `{:ok, [idp_id]}` or
      `{:error, reason}`. Naming an IdP outside the set is 403; a `trace_id`
      outside it is 404, the same as one that expired, because trace ids travel
      — they are the `?error_id=` a user pastes into a support ticket.
    * `:actor` — `{Mod, :fun}` returning a string for the audit line. Defaults
      to `conn.assigns[:ex_saml_actor]`.
    * `:require_actor` — refuse when no actor can be resolved. Defaults to true.
    * `:allow_global_scope` — permit the global switch. Defaults to false, so a
      tenant-scoped mount cannot turn debug on for everyone.
    * `:allow_unredacted` — permit `?redact=false` on a trace. Defaults to
      false: an unredacted trace contains the authorization code, which is a
      live bearer credential, and the session nonces.
    * `:allow_payload_download` — permit reading the captured `SAMLResponse`.
      Defaults to true; it is the point of the tool.
    * `:allow_node_local` — permit writes with no cache configured. Defaults to
      false, since enabling debug on one node of several is a support trap.
    * `:max_debug_ttl_ms` — cap on `ttl_ms`. Defaults to 4 hours.
    * `:default_locale`, `:audit_level`, `:audit_sink`.

  Options may also be given under `config :ex_saml, debug_api: [...]`; mount
  options win. Because both Plug's and Phoenix's `forward` call `init/1` at
  compile time, `{Mod, :fun}` tuples work everywhere while anonymous functions
  only work with `init_mode: :runtime`.

  Every request that reaches the pipeline emits one audit line, marked
  `pii=true` when it handed over a payload or an unredacted trace. An unhandled
  error is logged at `:error` instead, and re-raised for the host's reporter.
  """

  use Plug.Router, copy_opts_to_assign: :ex_saml_debug_api
  use Plug.ErrorHandler

  require Logger

  alias ExSaml.Debug
  alias ExSaml.Debug.Access
  alias ExSaml.Debug.Audit
  alias ExSaml.Debug.JSON
  alias ExSaml.Debug.View
  alias ExSaml.Error
  alias ExSaml.Helper

  @max_body_bytes 64_000

  plug(:put_opts)
  plug(:fetch_query_params)
  plug(:match)
  # Before the gates, so a refusal is audited too.
  plug(:audit)
  plug(:validate_ids)
  plug(:put_actor)
  plug(:authorize)
  plug(:dispatch)

  @impl Plug
  def init(opts) do
    Access.validate!(opts)
    opts
  end

  # ---------------------------------------------------------------------------
  # Debug switch
  # ---------------------------------------------------------------------------

  get "/debug" do
    body =
      case allowed(conn) do
        :all ->
          View.debug_all(Debug.status())

        ids ->
          View.debug_scoped(Debug.enabled?(), Enum.map(ids, &{&1, Debug.scope_status(&1)}))
      end

    send_json(conn, 200, body)
  end

  put "/debug" do
    with :ok <- require_global(conn), do: do_enable(conn, nil)
  end

  delete "/debug" do
    with :ok <- require_global(conn),
         :ok <- require_cache(conn) do
      Debug.disable()
      send_resp(conn, 204, "")
    end
  end

  put "/debug/idps/:idp_id" do
    do_enable(conn, idp_id)
  end

  delete "/debug/idps/:idp_id" do
    with :ok <- require_cache(conn) do
      Debug.disable(idp_id)
      send_resp(conn, 204, "")
    end
  end

  # ---------------------------------------------------------------------------
  # Failures
  # ---------------------------------------------------------------------------

  get "/idps/:idp_id/failures" do
    if Helper.get_idp(idp_id) do
      send_json(conn, 200, View.failures(idp_id, Debug.failures(idp_id)))
    else
      # `failures/1` answers [] for an unknown IdP and a quiet one alike.
      send_error(conn, 404, :unknown_idp, "No IdP is configured with this id.")
    end
  end

  get "/failures/:trace_id" do
    with {:ok, capture} <- capture(conn, trace_id),
         {:ok, locale} <- locale(conn) do
      send_json(conn, 200, View.failure(capture, locale, payload_href(conn, trace_id)))
    end
  end

  get "/failures/:trace_id/saml_response" do
    with :ok <- require_payload_download(conn),
         {:ok, capture} <- capture(conn, trace_id),
         {:ok, base64} <- payload(conn, capture),
         {:ok, format} <- format(conn) do
      case format do
        :json -> send_json(Audit.pii(conn), 200, View.saml_response(capture, base64))
        :xml -> send_xml(conn, trace_id)
      end
    end
  end

  post "/failures/:trace_id/replay" do
    with {:ok, capture} <- capture(conn, trace_id),
         {:ok, params} <- params(conn),
         {:ok, now} <- params |> Access.now() |> bad_request(conn) do
      replay(conn, trace_id, capture, now)
    end
  end

  # ---------------------------------------------------------------------------
  # Traces
  # ---------------------------------------------------------------------------

  get "/traces/:trace_id" do
    with {:ok, redact?} <- redact(conn),
         {:ok, events} <- Access.scoped_trace(trace_id, allowed(conn)) |> not_found(conn) do
      conn = if redact?, do: conn, else: Audit.pii(conn)
      events = if redact?, do: Debug.redact_trace(events), else: events

      send_json(conn, 200, View.trace(trace_id, events, redact?))
    end
  end

  # ---------------------------------------------------------------------------
  # Validation policy
  # ---------------------------------------------------------------------------

  get "/validation" do
    send_json(conn, 200, View.validation())
  end

  match _ do
    send_error(conn, 404, :not_found, "No such route.")
  end

  # ---------------------------------------------------------------------------
  # Plugs
  # ---------------------------------------------------------------------------

  defp put_opts(conn, _opts),
    do: put_private(conn, :ex_saml_debug_opts, Access.build(conn.assigns[:ex_saml_debug_api]))

  defp audit(conn, _opts), do: Audit.attach(conn, opts(conn))

  defp validate_ids(conn, _opts) do
    idp_id = conn.params["idp_id"]
    trace_id = conn.params["trace_id"]

    cond do
      not is_nil(idp_id) and not Access.valid_idp_id?(idp_id) ->
        halt_with(conn, 400, :invalid_identifier, "idp_id is not a valid identifier.")

      not is_nil(trace_id) and not Access.valid_trace_id?(trace_id) ->
        halt_with(conn, 400, :invalid_identifier, "trace_id is not a valid identifier.")

      true ->
        conn
    end
  end

  defp put_actor(conn, _opts) do
    opts = opts(conn)

    case Access.actor(conn, opts) do
      actor when is_binary(actor) and actor != "" ->
        put_private(conn, :ex_saml_debug_actor, actor)

      _ ->
        if opts.require_actor do
          halt_with(conn, 403, :actor_required, "This request must name an actor.")
        else
          conn
        end
    end
  end

  defp authorize(conn, _opts) do
    case Access.authorize(conn, opts(conn)) do
      {:ok, allowed} ->
        conn = put_private(conn, :ex_saml_debug_allowed, allowed)
        check_idp_scope(conn, conn.params["idp_id"], allowed)

      {:error, :unauthenticated} ->
        halt_with(conn, 401, :unauthenticated, "This request is not authenticated.")

      {:error, reason} ->
        # The reason is for our logs, not for the caller.
        Logger.debug("[ExSaml.DebugRouter] authorization refused: #{inspect(reason)}")
        halt_with(conn, 403, :forbidden, "This actor may not use the SAML debug API.")
    end
  end

  defp check_idp_scope(conn, nil, _allowed), do: conn

  defp check_idp_scope(conn, idp_id, allowed) do
    if Access.allowed?(allowed, idp_id),
      do: conn,
      else: halt_with(conn, 403, :forbidden_idp, "This actor may not see this IdP.")
  end

  # ---------------------------------------------------------------------------
  # Route helpers
  # ---------------------------------------------------------------------------

  defp do_enable(conn, idp_id) do
    with {:ok, params} <- params(conn),
         {:ok, settings} <- Access.settings_opts(params) |> bad_request(conn),
         {:ok, ttl} <- Access.ttl_ms(params, opts(conn)) |> bad_request(conn),
         :ok <- require_cache(conn) do
      enable_opts =
        settings
        |> put_opt(:idp_id, idp_id)
        |> put_opt(:ttl, ttl)

      {:ok, result} = Debug.enable(enable_opts)

      remaining = DateTime.diff(result.expires_at, DateTime.utc_now(), :millisecond)

      send_json(conn, 200, View.enabled(result, max(remaining, 0)))
    end
  end

  defp put_opt(opts, _key, nil), do: opts
  defp put_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp replay(conn, trace_id, capture, now) do
    evaluated_at = now || capture[:received_at]
    replay_opts = if now, do: [now: now], else: []

    case Debug.replay(trace_id, replay_opts) do
      {:ok, assertion} ->
        send_json(conn, 200, View.replay_ok(trace_id, evaluated_at, assertion))

      # `step: :replay` means the replay could not be attempted at all.
      {:error, %Error{step: :replay, reason: reason} = error} ->
        replay_refused(conn, reason, error)

      # Anything else: it ran and the response still fails. A result, not an error.
      {:error, %Error{} = error} ->
        send_json(conn, 200, View.replay_error(trace_id, evaluated_at, error))
    end
  end

  defp replay_refused(conn, :capture_not_found, _error),
    do: send_error(conn, 404, :capture_not_found, "No capture exists for this trace.")

  defp replay_refused(conn, :payload_not_captured, _error),
    do:
      send_error(
        conn,
        404,
        :payload_not_captured,
        "This flow was captured without its SAMLResponse."
      )

  defp replay_refused(conn, :unknown_idp, error),
    do:
      send_error(conn, 409, :unknown_idp, "This capture's IdP is no longer configured.", %{
        "idp_id" => error.idp_id
      })

  defp replay_refused(conn, reason, _error),
    do: send_error(conn, 409, reason, "This capture cannot be replayed.")

  defp capture(conn, trace_id) do
    case Access.scoped_capture(trace_id, allowed(conn)) do
      {:ok, capture} ->
        {:ok, capture}

      {:error, :not_found} ->
        send_error(conn, 404, :capture_not_found, "No capture exists for this trace.")
    end
  end

  defp payload(conn, capture) do
    case capture[:saml_response] do
      payload when is_binary(payload) ->
        {:ok, payload}

      _ ->
        send_error(
          conn,
          404,
          :payload_not_captured,
          "This flow was captured without its SAMLResponse."
        )
    end
  end

  # Built from the mount prefix, so the link is right wherever it is forwarded.
  defp payload_href(conn, trace_id),
    do: "/" <> Enum.join(conn.script_name ++ ["failures", trace_id, "saml_response"], "/")

  defp send_xml(conn, trace_id) do
    case Debug.saml_response(trace_id, decode: true) do
      xml when is_binary(xml) ->
        conn
        |> Audit.pii()
        |> put_resp_header(
          "content-disposition",
          ~s(attachment; filename="saml-response-#{trace_id}.xml")
        )
        |> put_resp_content_type("application/xml")
        |> send_resp(200, xml)

      _ ->
        # Distinct from "not captured": present, but not decodable to text.
        send_error(
          conn,
          409,
          :payload_not_decodable,
          "This SAMLResponse could not be decoded; fetch it with ?format=json."
        )
    end
  end

  # ---------------------------------------------------------------------------
  # Parameters
  # ---------------------------------------------------------------------------

  defp params(conn) do
    case conn.body_params do
      %Plug.Conn.Unfetched{} -> read_body_params(conn)
      %{} = body -> {:ok, Map.merge(conn.query_params, body)}
    end
  end

  # Plain-Plug mounts only: Phoenix has already parsed the body.
  defp read_body_params(conn) do
    case Plug.Conn.read_body(conn, length: @max_body_bytes) do
      {:ok, "", _conn} ->
        {:ok, conn.query_params}

      {:ok, body, _conn} ->
        decode_body(conn, body)

      {:more, _partial, _conn} ->
        send_error(conn, 413, :request_too_large, "The request body is too large.")

      _ ->
        send_error(conn, 400, :invalid_json, "The request body could not be read.")
    end
  end

  defp decode_body(conn, body) do
    case JSON.decode(body) do
      {:ok, %{} = params} -> {:ok, Map.merge(conn.query_params, params)}
      {:ok, _other} -> send_error(conn, 400, :invalid_json, "Expected a JSON object.")
      {:error, :no_json_decoder} -> no_decoder(conn)
      {:error, _} -> send_error(conn, 400, :invalid_json, "The request body is not valid JSON.")
    end
  end

  defp no_decoder(conn) do
    send_error(conn, 415, :json_body_unsupported, """
    No JSON decoder is available. Add :jason to your dependencies, run on \
    OTP 27+, or configure config :ex_saml, debug_api: [json_decoder: {Mod, :fun}].\
    """)
  end

  defp locale(conn) do
    case Access.locale(conn.query_params, opts(conn)) do
      {:ok, locale} ->
        {:ok, locale}

      {:error, known} ->
        send_error(conn, 400, :invalid_locale, "Unknown locale.", %{"allowed" => known})
    end
  end

  defp format(conn) do
    case conn.query_params["format"] do
      nil -> {:ok, format_from_accept(conn)}
      "json" -> {:ok, :json}
      "xml" -> {:ok, :xml}
      _ -> send_error(conn, 400, :invalid_format, "format must be json or xml.")
    end
  end

  defp format_from_accept(conn) do
    accept = conn |> get_req_header("accept") |> List.first() || ""

    if String.contains?(accept, "xml"), do: :xml, else: :json
  end

  defp redact(conn) do
    opts = opts(conn)

    case conn.query_params["redact"] do
      "false" when not opts.allow_unredacted ->
        # An unredacted trace carries the authorization code, a live credential.
        send_error(
          conn,
          403,
          :unredacted_forbidden,
          "This mount does not allow unredacted traces."
        )

      "false" ->
        {:ok, false}

      _ ->
        {:ok, true}
    end
  end

  # ---------------------------------------------------------------------------
  # Gates
  # ---------------------------------------------------------------------------

  defp require_global(conn) do
    if Access.global_allowed?(allowed(conn), opts(conn)) do
      :ok
    else
      send_error(
        conn,
        403,
        :global_scope_forbidden,
        "This mount does not allow changing the global debug switch."
      )
    end
  end

  defp require_payload_download(conn) do
    if opts(conn).allow_payload_download do
      :ok
    else
      send_error(
        conn,
        403,
        :payload_download_forbidden,
        "This mount does not allow downloading captured SAML responses."
      )
    end
  end

  defp require_cache(conn) do
    cond do
      not is_nil(Debug.config().cache) ->
        :ok

      opts(conn).allow_node_local ->
        :ok

      true ->
        # `enable/1` would fall back to a node-local flag, arming one node of
        # several behind a load balancer.
        send_error(
          conn,
          409,
          :cache_not_configured,
          "No cache is configured, so debug mode cannot be set for the cluster."
        )
    end
  end

  defp not_found({:ok, value}, _conn), do: {:ok, value}

  defp not_found({:error, :not_found}, conn),
    do: send_error(conn, 404, :trace_not_found, "No trace exists for this id.")

  defp bad_request({:ok, value}, _conn), do: {:ok, value}

  defp bad_request({:error, {:invalid_parameter, key, nil}}, conn),
    do: send_error(conn, 400, :invalid_parameter, "#{key} is not valid.", %{"parameter" => key})

  defp bad_request({:error, {:invalid_parameter, key, allowed}}, conn),
    do:
      send_error(conn, 400, :invalid_parameter, "#{key} is not valid.", %{
        "parameter" => key,
        "allowed" => allowed
      })

  defp bad_request({:error, {:ttl_too_large, max}}, conn),
    do:
      send_error(conn, 400, :ttl_too_large, "ttl_ms is above this mount's cap.", %{
        "max_ms" => max
      })

  # ---------------------------------------------------------------------------
  # Responses
  # ---------------------------------------------------------------------------

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> cache_header()
    |> send_resp(status, JSON.encode_to_iodata!(body))
  end

  defp send_error(conn, status, code, message, extras \\ %{}) do
    extras =
      extras
      |> maybe_put("trace_id", conn.params["trace_id"])
      |> maybe_put("idp_id", conn.params["idp_id"])

    send_json(conn, status, View.error(code, String.trim(message), extras))
  end

  defp halt_with(conn, status, code, message),
    do: conn |> send_error(status, code, message) |> halt()

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put_new(map, key, value)

  # Says why a read came back empty, without a support ticket.
  defp cache_header(conn) do
    if Debug.config().cache,
      do: conn,
      else: put_resp_header(conn, "x-ex-saml-cache", "none")
  end

  defp opts(conn), do: conn.private[:ex_saml_debug_opts] || Access.build([])
  defp allowed(conn), do: conn.private[:ex_saml_debug_allowed] || []

  @impl Plug.ErrorHandler
  def handle_errors(conn, %{reason: reason}) do
    Logger.error("[ExSaml.DebugRouter] unhandled error: #{inspect(reason)}")

    send_json(conn, conn.status || 500, View.error(:internal_error, "Something went wrong."))
  end
end
