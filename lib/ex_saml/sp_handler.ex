defmodule ExSaml.SPHandler do
  @moduledoc """
  Handles Service Provider SAML responses: metadata generation, assertion consumption,
  and logout handling.

  ## Functions

    * `send_metadata/1` - Returns SP metadata XML for the given IdP
    * `consume_signin_response/2` - Processes the IdP sign-in response and returns the assertion
    * `handle_logout_response/1` - Processes the IdP logout response
    * `handle_logout_request/1` - Processes an IdP-initiated logout request

  ## Callback contract

  After consuming the IdP response, the router-facing `consume_signin_response/1`
  always redirects the browser to the target URL with exactly one of:

    * `?code=<authorization_code>` on success — redeem it once with
      `ExSaml.Assertion.get_from_code/1`
    * `?error_id=<id>` on failure — redeem it once with `ExSaml.Error.get_from_id/1`

  Both are random, single-use and expire. The failure path also keeps the legacy
  `ex_saml_error` session entry for existing consumers, but the session is not a
  reliable channel across the cross-site IdP POST: prefer `error_id`.
  """

  require Logger
  import Plug.Conn

  alias ExSaml.{
    Assertion,
    AuthorizationCodeCache,
    Debug,
    Error,
    Helper,
    IdpData,
    RelayStateCache,
    State,
    Subject
  }

  import ExSaml.Helper, only: [get_idp: 1]
  import ExSaml.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 5, redirect: 3]

  @doc "Returns the SP metadata XML for the IdP in `conn.private[:ex_saml_idp]`."
  # metadata is generated from SP config by Helper.sp_metadata/1, not from user input.
  # sobelow_skip ["XSS.SendResp"]
  def send_metadata(conn) do
    %IdpData{} = idp = conn.private[:ex_saml_idp]
    %IdpData{sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)
    metadata = Helper.sp_metadata(sp)

    conn
    |> put_resp_header("content-type", "text/xml")
    |> send_resp(200, metadata)
  end

  @doc """
  Processes the IdP sign-in response and extracts the SAML assertion.

  On success returns
  `{:ok, %{flow: flow, assertion: assertion, nonce: nonce, user_token: token, redirect_uri: uri}}`
  where:

    * `flow` is `:idp_initiated` or `:sp_initiated` and reflects which SAML flow
      produced the response (deduced from the assertion's `SubjectConfirmationData`
      `InResponseTo` — empty means IdP-initiated).
    * `nonce` is the AuthnRequest-bound SAML nonce for SP-initiated flows, and
      `nil` for IdP-initiated flows (no AuthnRequest exists in that case, so no
      nonce is generated; downstream consumers must accept `nil` for the
      IdP-initiated case).

  On failure returns `{:error, reason}`. Possible reasons include
  `:idp_initiated_not_allowed`, `:invalid_target_url`, `:invalid_relay_state`,
  `:invalid_idp_id`, `:missing_saml_response`, and every decoding / validation
  reason produced by `ExSaml.Core.Sp.validate_assertion/3`.
  """
  # Router-facing clause: matches when the SP router dispatched here with
  # `idp_id` in path params. Performs the full SAML flow AND handles the
  # connection: persists the assertion, generates an authorization code,
  # and redirects to the target URL. Always returns a `%Plug.Conn{}`.
  #
  # Fails closed: any exception raised while consuming the response is turned
  # into an `error_id` redirect (never a bare 500), so the consumer always gets
  # something to diagnose.
  def consume_signin_response(%{params: %{"idp_id" => idp_id}} = conn)
      when is_bitstring(idp_id) do
    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)

    try do
      do_consume_signin_response(conn, idp_id, rls, relay_state)
    rescue
      e ->
        unexpected_error(conn, idp_id, relay_state, :error, e, __STACKTRACE__)
    catch
      kind, value ->
        unexpected_error(conn, idp_id, relay_state, kind, value, __STACKTRACE__)
    end
  end

  # Library-facing clause: pure decode+validate. Returns the assertion data
  # as a tuple — caller is responsible for any conn handling. Useful when
  # an app wants to drive the post-consume flow itself.
  def consume_signin_response(conn, %IdpData{id: idp_id, sp_config: sp_cfg} = idp_data) do
    sp = ensure_sp_uris_set(sp_cfg, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]

    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)
    relay_entry = RelayStateCache.get(relay_state)
    user_token = relay_entry[:user_token]
    redirect_uri = relay_entry[:redirect_uri]

    # The debug id only exists when a report is being built for this IdP, so
    # consumers never see a dangling id that resolves to nothing.
    debug_id = if Debug.enabled?(idp_id), do: debug_id(conn, relay_state)
    Debug.put_context(idp_id, debug_id)

    Debug.log(:response_received, fn ->
      %{
        idp_id: idp_id,
        debug_id: debug_id,
        relay_state_raw: rls,
        relay_state: relay_state,
        relay_cache_hit: not is_nil(relay_entry),
        relay_cache_entry: relay_entry,
        method: conn.method,
        host: conn.host,
        request_path: conn.request_path,
        origin: get_req_header(conn, "origin"),
        referer: get_req_header(conn, "referer"),
        user_agent: get_req_header(conn, "user-agent"),
        cookie_names: conn |> fetch_cookies() |> Map.get(:req_cookies) |> Map.keys(),
        body_param_keys: Map.keys(conn.body_params),
        saml_encoding: saml_encoding,
        saml_response: saml_response,
        session: session_snapshot(conn),
        consume_uri: sp.consume_uri,
        entity_id: sp.entity_id
      }
    end)

    decoded = Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response)

    Debug.log(:decode_result, fn ->
      case decoded do
        {:ok, assertion} -> %{result: :ok, assertion: assertion}
        {:error, reason} -> %{result: :error, reason: reason}
      end
    end)

    with {:ok, assertion} <- tag_step(decoded, :decode),
         {:ok, flow, nonce} <-
           tag_step(validate_authresp(conn, idp_data, assertion, relay_state), :validate_authresp) do
      {:ok,
       %{
         flow: flow,
         assertion: %Assertion{assertion | idp_id: idp_id},
         nonce: nonce,
         user_token: user_token,
         redirect_uri: redirect_uri
       }}
    else
      {:error, error} -> {:error, error}
    end
  end

  defp do_consume_signin_response(conn, idp_id, rls, relay_state) do
    with {:ok, idp_data} <- fetch_idp(idp_id),
         :ok <- maybe_redirect_to_start_url(conn, rls),
         {:ok, %{assertion: assertion, nonce: nonce, flow: flow}} <-
           consume_signin_response(conn, idp_data) do
      nameid = assertion.subject.name
      assertion_key = {idp_data.id, maybe_idp_user_id(assertion) || nameid}
      conn = State.put_assertion(conn, assertion_key, assertion)
      {target_url, target_source} = auth_target_url(conn, assertion, relay_state)

      RelayStateCache.delete(relay_state)

      redirect_with_authorization_code(conn, %{
        idp_id: idp_data.id,
        flow: flow,
        target_url: target_url,
        target_source: target_source,
        assertion_key: assertion_key,
        nonce: nonce,
        relay_state: relay_state
      })
    else
      {:halted, conn} ->
        conn

      {:error, error} ->
        redirect_with_error(conn, relay_state, error)

      # Defensive fallback: unreachable today (Dialyzer flags it as such), but
      # kept so that any future change introducing a new return shape from the
      # `with` chain fails closed with a 403 instead of crashing the request
      # with a `WithClauseError`. Auth endpoints should fail closed.
      _ ->
        conn |> send_resp(403, "access_denied")
    end
  end

  defp fetch_idp(idp_id) do
    case get_idp(idp_id) do
      %IdpData{} = idp -> {:ok, idp}
      _ -> tag_step({:error, {:unknown_idp, idp_id}}, :idp_lookup)
    end
  end

  # Records which step of the flow produced an error, so `%ExSaml.Error{step: _}`
  # can be filled without threading the information through every return value.
  defp tag_step({:error, _} = error, step) do
    Process.put(:ex_saml_error_step, step)
    error
  end

  defp tag_step(other, _step), do: other

  defp maybe_idp_user_id(%{attributes: %{"idp_user_id" => idp_user_id}}), do: idp_user_id
  defp maybe_idp_user_id(_), do: nil

  defp maybe_redirect_to_start_url(_, nil), do: :ok

  defp maybe_redirect_to_start_url(conn, rls) do
    if String.contains?(rls, "https://start-from:") do
      {:halted, redirect(conn, 302, String.replace(rls, "start-from:", ""))}
    else
      :ok
    end
  end

  defp redirect_with_authorization_code(conn, ctx) do
    code = State.gen_id()
    {_idp_id, debug_id} = Debug.context()
    debug? = Debug.enabled?(ctx.idp_id)

    if debug?, do: Debug.link_code(code, debug_id, ctx.idp_id)

    AuthorizationCodeCache.put_new!(code, %{
      ex_saml_assertion_key: ctx.assertion_key,
      saml_nonce_candidate: ctx.nonce,
      debug_id: if(debug?, do: debug_id)
    })

    Debug.log(:code_issued, ctx.idp_id, fn ->
      %{
        idp_id: ctx.idp_id,
        debug_id: debug_id,
        code: code,
        assertion_key: ctx.assertion_key,
        nonce: ctx.nonce,
        flow: ctx.flow,
        target_url: ctx.target_url,
        target_source: ctx.target_source,
        relay_state: ctx.relay_state,
        code_ttl: AuthorizationCodeCache.ttl()
      }
    end)

    redirect(conn, 302, "#{ctx.target_url}?code=#{code}")
  end

  # Failure path, symmetric with the success path: the error is stored under a
  # random single-use `error_id` and the browser is redirected with
  # `?error_id=<id>`. The legacy session entry is kept for compatibility.
  defp redirect_with_error(conn, relay_state, reason) do
    {target_url, target_source} =
      case reason do
        :invalid_target_url -> {target_url(), :fallback}
        _ -> target_url_with_source(conn, relay_state)
      end

    {idp_id, debug_id} = Debug.context()
    step = Process.delete(:ex_saml_error_step) || :validate_authresp

    {error_id, error} =
      Error.new(%{
        reason: reason,
        step: if(reason == :invalid_target_url, do: :target_url, else: step),
        flow: flow_for(reason),
        idp_id: idp_id,
        relay_state: relay_state,
        debug_id: debug_id
      })
      |> Error.issue()

    Debug.log(:error_issued, idp_id, fn ->
      %{
        idp_id: idp_id,
        debug_id: debug_id,
        error_id: error_id,
        reason: reason,
        step: error.step,
        target_url: target_url,
        target_source: target_source,
        session: session_snapshot(conn),
        error_ttl: ExSaml.ErrorCache.ttl()
      }
    end)

    conn
    |> put_session("ex_saml_error", {:error, reason})
    |> redirect(302, Error.append_error_id(target_url, error_id))
  end

  defp unexpected_error(conn, idp_id, relay_state, kind, value, stacktrace) do
    formatted = Exception.format(kind, value, stacktrace)
    Logger.error("[ExSaml] consume_signin_response crashed: #{formatted}")

    Debug.log(:unexpected_error, %{idp_id: idp_id, relay_state: relay_state, error: formatted})
    Process.put(:ex_saml_error_step, :unexpected)

    message =
      case kind do
        :error -> Exception.message(Exception.normalize(:error, value, stacktrace))
        _ -> inspect(value)
      end

    redirect_with_error(conn, relay_state, {:exception, message})
  end

  defp flow_for(:idp_initiated_not_allowed), do: :idp_initiated
  defp flow_for(:invalid_target_url), do: :idp_initiated
  defp flow_for(:invalid_relay_state), do: :sp_initiated
  defp flow_for(:invalid_idp_id), do: :sp_initiated
  defp flow_for(_), do: nil

  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, ""), do: {"/", :default}
  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, url), do: {url, :relay_state}

  defp auth_target_url(conn, _assertion, relay_state) do
    cond do
      url = get_session(conn, "target_url") -> {url, :session}
      url = RelayStateCache.get(relay_state)[:target_url] -> {url, :cache}
      true -> {"/", :default}
    end
  end

  # SP-initiated flows reuse the relay state as debug id (it was generated by
  # `ExSaml.AuthHandler` and already carries the AuthnRequest step). IdP-initiated
  # flows have no relay state of ours, so a fresh id is generated per request.
  defp debug_id(conn, relay_state) do
    ours? =
      relay_state != "" and
        (get_session(conn, "relay_state") == relay_state or
           not is_nil(RelayStateCache.get(relay_state)))

    if ours?, do: relay_state, else: State.gen_id()
  end

  defp session_snapshot(conn) do
    %{
      relay_state: get_session(conn, "relay_state"),
      idp_id: get_session(conn, "idp_id"),
      target_url: get_session(conn, "target_url"),
      saml_nonce_present: not is_nil(get_session(conn, "saml_nonce")),
      assertion_key_present: not is_nil(get_session(conn, "ex_saml_assertion_key"))
    }
  rescue
    # `get_session/2` raises when the session was never fetched on this conn.
    ArgumentError -> %{unavailable: true}
  end

  # IdP-initiated flow auth response. Tagged as `:idp_initiated` with a `nil`
  # nonce since there is no AuthnRequest to bind a nonce to in this flow.
  @doc false
  def validate_authresp(_conn, idp_data, %{subject: %{in_response_to: ""}}, relay_state) do
    result =
      cond do
        !idp_data.allow_idp_initiated_flow ->
          {:error, :idp_initiated_not_allowed}

        idp_data.allowed_target_urls && relay_state not in idp_data.allowed_target_urls ->
          {:error, :invalid_target_url}

        true ->
          {:ok, :idp_initiated, nil}
      end

    Debug.log(:validate_authresp_result, idp_data.id, fn ->
      %{
        idp_id: idp_data.id,
        flow: :idp_initiated,
        result: result,
        relay_state: relay_state,
        allow_idp_initiated_flow: idp_data.allow_idp_initiated_flow,
        allowed_target_urls: idp_data.allowed_target_urls
      }
    end)

    result
  end

  # SP-initiated flow auth response.
  def validate_authresp(conn, %IdpData{id: idp_id}, assertion, relay_state) do
    cached = RelayStateCache.get(relay_state)

    {rs_in_session, rs_source} =
      with_source(get_session(conn, "relay_state"), cached[:relay_state])

    {idp_id_in_session, idp_source} = with_source(get_session(conn, "idp_id"), cached[:idp_id])

    {saml_nonce_in_session, nonce_source} =
      with_source(get_session(conn, "saml_nonce"), cached[:saml_nonce])

    {authn_request_id, request_id_source} =
      with_source(get_session(conn, "authn_request_id"), cached[:authn_request_id])

    result =
      cond do
        rs_in_session == nil || rs_in_session != relay_state ->
          {:error, :invalid_relay_state}

        idp_id_in_session == nil || idp_id_in_session != idp_id ->
          {:error, :invalid_idp_id}

        not in_response_to_ok?(authn_request_id, assertion) ->
          {:error, :bad_in_response_to}

        true ->
          {:ok, :sp_initiated, saml_nonce_in_session}
      end

    Debug.log(:validate_authresp_result, idp_id, fn ->
      %{
        idp_id: idp_id,
        flow: :sp_initiated,
        result: result,
        relay_state: relay_state,
        relay_cache_hit: not is_nil(cached),
        relay_state_expected: rs_in_session,
        relay_state_source: rs_source,
        idp_id_expected: idp_id_in_session,
        idp_id_source: idp_source,
        saml_nonce: saml_nonce_in_session,
        saml_nonce_source: nonce_source,
        authn_request_id: authn_request_id,
        authn_request_id_source: request_id_source,
        in_response_to: assertion.subject.in_response_to
      }
    end)

    result
  end

  # Profiles §4.1.4.3. A stored `nil` means the relay-state entry predates
  # AuthnRequest-id tracking — a rolling deploy, or a consumer driving
  # `validate_authresp/4` without going through `ExSaml.AuthHandler` — so it
  # skips rather than rejects. An empty `InResponseTo` is an unsolicited
  # response and is handled by the IdP-initiated clause above, never here.
  defp in_response_to_ok?(nil, _assertion), do: true
  defp in_response_to_ok?(_expected, %{subject: %{in_response_to: ""}}), do: true

  defp in_response_to_ok?(expected, %{subject: %{in_response_to: actual}}),
    do: to_string(expected) == to_string(actual)

  defp with_source(nil, nil), do: {nil, :none}
  defp with_source(nil, cached), do: {cached, :cache}
  defp with_source(value, _), do: {value, :session}

  @doc "Processes the IdP logout response and redirects to the target URL."
  # Error details are logged server-side only; the response body is a static string, not user input.
  # sobelow_skip ["XSS.SendResp"]
  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    # Handle both POST and Redirect
    saml_response = conn.body_params["SAMLResponse"] || Map.get(conn.params, "SAMLResponse")
    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)

    with {:ok, _payload} <- Helper.decode_idp_signout_resp(sp, saml_encoding, saml_response),
         ^relay_state when relay_state != nil <- get_session(conn, "relay_state"),
         ^idp_id <- get_session(conn, "idp_id"),
         target_url when target_url != nil <- get_session(conn, "target_url") do
      conn
      |> configure_session(drop: true)
      |> redirect(302, target_url)
    else
      error ->
        Logger.error("[ExSaml] Logout response validation failed: #{inspect(error)}")

        Debug.log(:logout_response_failed, idp_id, fn ->
          %{
            idp_id: idp_id,
            error: error,
            relay_state: relay_state,
            saml_encoding: saml_encoding,
            saml_response: saml_response,
            session: session_snapshot(conn)
          }
        end)

        conn |> send_resp(403, "invalid_request")
    end
  end

  @doc "Handles an IdP-initiated logout request."
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{idp_metadata: idp_meta, sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_request = conn.body_params["SAMLRequest"]
    rls = conn.body_params["RelayState"]
    relay_state = safe_decode_www_form(rls)

    case Helper.decode_idp_signout_req(sp, saml_encoding, saml_request) do
      {:ok, %ExSaml.Core.LogoutRequest{name: nameid}} ->
        assertion_key = {idp_id, nameid}

        {conn, return_status} =
          case State.get_assertion(conn, assertion_key) do
            %Assertion{idp_id: ^idp_id, subject: %Subject{name: ^nameid}} ->
              conn = State.delete_assertion(conn, assertion_key)
              {conn, :success}

            _ ->
              {conn, :denied}
          end

        {idp_signout_url, resp_xml_frag} =
          Helper.gen_idp_signout_resp(sp, idp_meta, return_status)

        conn
        |> configure_session(drop: true)
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          resp_xml_frag,
          relay_state
        )

      error ->
        Logger.error("#{inspect(error)}")

        Debug.log(:logout_request_failed, idp_id, fn ->
          %{
            idp_id: idp_id,
            error: error,
            relay_state: relay_state,
            saml_encoding: saml_encoding,
            saml_request: saml_request
          }
        end)

        {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_meta, :denied)

        conn
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          resp_xml_frag,
          relay_state
        )
    end
  end

  @doc """
  Returns the target URL from session or relay state cache, falling back
  to `target_url/0` (`Application.get_env(:ex_saml, :fallback_target_url, "/")`)
  when neither is set. Never returns `nil` — callers can safely pass the
  result to `Plug.Conn.put_resp_header/3`.
  """
  def target_url(conn, relay_state) do
    {url, _source} = target_url_with_source(conn, relay_state)
    url
  end

  @doc "Returns the fallback target URL from application config (defaults to `\"/\"`)."
  def target_url, do: Application.get_env(:ex_saml, :fallback_target_url, "/")

  defp target_url_with_source(conn, relay_state) do
    cond do
      url = get_session(conn, "target_url") -> {url, :session}
      url = RelayStateCache.get(relay_state)[:target_url] -> {url, :cache}
      true -> {target_url(), :fallback}
    end
  end

  defp safe_decode_www_form(nil), do: ""
  defp safe_decode_www_form(data), do: URI.decode_www_form(data)
end
