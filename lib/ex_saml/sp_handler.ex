defmodule ExSaml.SPHandler do
  @moduledoc """
  Handles Service Provider SAML responses: metadata generation, assertion consumption,
  and logout handling.

  ## Functions

    * `send_metadata/1` - Returns SP metadata XML for the given IdP
    * `consume_signin_response/2` - Processes the IdP sign-in response and returns the assertion
    * `handle_logout_response/1` - Processes the IdP logout response
    * `handle_logout_request/1` - Processes an IdP-initiated logout request
  """

  require Logger
  import Plug.Conn

  alias ExSaml.{
    Assertion,
    AuthorizationCodeCache,
    Helper,
    IdpData,
    RelayStateCache,
    State,
    Subject
  }

  alias ExSaml.Core.RedirectBindingSignature

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

    # NOTE: We should avoid this, as you can not decorate the
    # behaviour.
    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")

    # PROPOSAL:
    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     {:error, saml: :request_metadata_failed}
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
  `:invalid_idp_id`, and `:access_denied`.
  """
  # Router-facing clause: matches when the SP router dispatched here with
  # `idp_id` in path params. Performs the full SAML flow AND handles the
  # connection: persists the assertion, generates an authorization code,
  # and redirects to the target URL. Always returns a `%Plug.Conn{}`.
  def consume_signin_response(%{params: %{"idp_id" => idp_id}} = conn)
      when is_bitstring(idp_id) do
    idp_data = get_idp(idp_id)
    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)

    with :ok <- maybe_redirect_to_start_url(conn, rls),
         {:ok, %{assertion: assertion, nonce: nonce}} <-
           consume_signin_response(conn, idp_data) do
      nameid = assertion.subject.name
      assertion_key = {idp_data.id, maybe_idp_user_id(assertion) || nameid}
      conn = State.put_assertion(conn, assertion_key, assertion)
      target_url = auth_target_url(conn, assertion, relay_state)

      RelayStateCache.delete(relay_state)

      redirect_with_authorization_code(conn, target_url, assertion_key, nonce)
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

  # Library-facing clause: pure decode+validate. Returns the assertion data
  # as a tuple — caller is responsible for any conn handling. Useful when
  # an app wants to drive the post-consume flow itself.
  def consume_signin_response(conn, %IdpData{id: idp_id, sp_config: sp_cfg} = idp_data) do
    sp = ensure_sp_uris_set(sp_cfg, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]

    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)
    user_token = RelayStateCache.get(relay_state)[:user_token]
    redirect_uri = RelayStateCache.get(relay_state)[:redirect_uri]

    with {:ok, assertion} <- Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response),
         {:ok, flow, nonce} <- validate_authresp(conn, idp_data, assertion, relay_state) do
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

  defp redirect_with_authorization_code(conn, target_url, assertion_key, nonce) do
    code = State.gen_id()

    AuthorizationCodeCache.put_new!(code, %{
      ex_saml_assertion_key: assertion_key,
      saml_nonce_candidate: nonce
    })

    redirect(conn, 302, "#{target_url}?code=#{code}")
  end

  defp redirect_with_error(conn, _, :invalid_target_url) do
    conn
    |> put_session("ex_saml_error", {:error, :invalid_target_url})
    |> redirect(302, target_url())
  end

  defp redirect_with_error(conn, relay_state, error) do
    conn
    |> put_session("ex_saml_error", {:error, error})
    |> redirect(302, target_url(conn, relay_state))
  end

  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, ""), do: "/"
  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, url), do: url

  defp auth_target_url(conn, _assertion, relay_state) do
    get_session(conn, "target_url") || RelayStateCache.get(relay_state)[:target_url] || "/"
  end

  # IdP-initiated flow auth response. Tagged as `:idp_initiated` with a `nil`
  # nonce since there is no AuthnRequest to bind a nonce to in this flow.
  @doc false
  def validate_authresp(_conn, idp_data, %{subject: %{in_response_to: ""}}, relay_state) do
    cond do
      !idp_data.allow_idp_initiated_flow ->
        {:error, :idp_initiated_not_allowed}

      idp_data.allowed_target_urls && relay_state not in idp_data.allowed_target_urls ->
        {:error, :invalid_target_url}

      true ->
        {:ok, :idp_initiated, nil}
    end
  end

  # SP-initiated flow auth response.
  def validate_authresp(conn, %IdpData{id: idp_id}, _assertion, relay_state) do
    rs_in_session =
      get_session(conn, "relay_state") || RelayStateCache.get(relay_state)[:relay_state]

    idp_id_in_session = get_session(conn, "idp_id") || RelayStateCache.get(relay_state)[:idp_id]

    saml_nonce_in_session =
      get_session(conn, "saml_nonce") || RelayStateCache.get(relay_state)[:saml_nonce]

    cond do
      rs_in_session == nil || rs_in_session != relay_state ->
        {:error, :invalid_relay_state}

      idp_id_in_session == nil || idp_id_in_session != idp_id ->
        {:error, :invalid_idp_id}

      true ->
        {:ok, :sp_initiated, saml_nonce_in_session}
    end
  end

  @doc "Processes the IdP logout response and redirects to the target URL."
  # Error details are logged server-side only; the response body is a static string, not user input.
  # sobelow_skip ["XSS.SendResp"]
  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)

    # Handle both POST and Redirect
    saml_encoding = msg_param(conn, "SAMLEncoding")
    saml_response = msg_param(conn, "SAMLResponse")
    rls = msg_param(conn, "RelayState")
    relay_state = safe_decode_www_form(rls)

    with :ok <- verify_redirect_logout_response(conn, idp),
         {:ok, _payload} <- Helper.decode_idp_signout_resp(sp, saml_encoding, saml_response),
         ^relay_state when relay_state != nil <- get_session(conn, "relay_state"),
         ^idp_id <- get_session(conn, "idp_id"),
         target_url when target_url != nil <- get_session(conn, "target_url") do
      conn
      |> configure_session(drop: true)
      |> redirect(302, target_url)
    else
      error ->
        Logger.error("[ExSaml] Logout response validation failed: #{inspect(error)}")
        conn |> send_resp(403, "invalid_request")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  @doc "Handles an IdP-initiated logout request."
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{idp_metadata: idp_meta, sp_config: sp_cfg} = idp
    sp = ensure_sp_uris_set(sp_cfg, conn)

    # Handle both POST and Redirect
    saml_encoding = msg_param(conn, "SAMLEncoding")
    saml_request = msg_param(conn, "SAMLRequest")
    rls = msg_param(conn, "RelayState")
    relay_state = safe_decode_www_form(rls)

    with {:ok, sp} <- verify_redirect_logout_request(conn, idp, sp),
         {:ok, %ExSaml.Core.LogoutRequest{name: nameid, id: request_id}} <-
           Helper.decode_idp_signout_req(sp, saml_encoding, saml_request) do
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
        Helper.gen_idp_signout_resp(sp, idp_meta, return_status, request_id)

      conn
      |> configure_session(drop: true)
      |> send_saml_request(
        idp_signout_url,
        idp.use_redirect_for_req,
        resp_xml_frag,
        relay_state
      )
    else
      # The Redirect binding signature is missing or does not verify: the
      # request cannot be attributed to the IdP, so fail closed without
      # touching the session and without building a LogoutResponse.
      {:redirect_signature_error, reason} ->
        Logger.error("[ExSaml] Logout request signature verification failed: #{inspect(reason)}")
        conn |> send_resp(403, "invalid_request")

      error ->
        Logger.error("#{inspect(error)}")
        {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_meta, :denied)

        conn
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          resp_xml_frag,
          relay_state
        )
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # HTTP-Redirect binding carries its signature in the query string, not in
  # the XML (SAML 2.0 Bindings §3.4.4.1) — signed Redirect messages MUST have
  # the XML signature removed. So for GET requests the query signature is
  # verified against the IdP metadata certificates and, on success, the XML
  # signature check is disabled for this request. POST (HTTP-POST binding)
  # requests keep the XML signature check as-is.
  defp verify_redirect_logout_request(%Plug.Conn{method: "GET"} = conn, idp, sp) do
    if sp.idp_signs_logout_requests do
      case RedirectBindingSignature.verify(conn.query_string, idp.certs) do
        :ok -> {:ok, %{sp | idp_signs_logout_requests: false}}
        {:error, reason} -> {:redirect_signature_error, reason}
      end
    else
      {:ok, sp}
    end
  end

  defp verify_redirect_logout_request(_conn, _idp, sp), do: {:ok, sp}

  # LogoutResponses are verified opt-in, mirroring the XML-signature policy of
  # `Core.Sp.validate_logout_response/2` (verify only when a signature is
  # present): a query signature, when sent, must verify; its absence is not an
  # error.
  defp verify_redirect_logout_response(%Plug.Conn{method: "GET"} = conn, idp) do
    if Map.get(conn.params, "Signature") do
      case RedirectBindingSignature.verify(conn.query_string, idp.certs) do
        :ok -> :ok
        {:error, reason} -> {:redirect_signature_error, reason}
      end
    else
      :ok
    end
  end

  defp verify_redirect_logout_response(_conn, _idp), do: :ok

  @doc """
  Returns the target URL from session or relay state cache, falling back
  to `target_url/0` (`Application.get_env(:ex_saml, :fallback_target_url, "/")`)
  when neither is set. Never returns `nil` — callers can safely pass the
  result to `Plug.Conn.put_resp_header/3`.
  """
  def target_url(conn, relay_state) do
    get_session(conn, "target_url") || RelayStateCache.get(relay_state)[:target_url] ||
      target_url()
  end

  @doc "Returns the fallback target URL from application config (defaults to `\"/\"`)."
  def target_url, do: Application.get_env(:ex_saml, :fallback_target_url, "/")

  defp safe_decode_www_form(nil), do: ""
  defp safe_decode_www_form(data), do: URI.decode_www_form(data)

  # Reads a SAML message parameter from the body (HTTP-POST binding) with a
  # fallback to the query string (HTTP-Redirect binding). Body params may be
  # unfetched when no Plug.Parsers ran (e.g. a bare GET outside Phoenix).
  defp msg_param(conn, name) do
    case conn.body_params do
      %Plug.Conn.Unfetched{} -> Map.get(conn.params, name)
      body_params -> body_params[name] || Map.get(conn.params, name)
    end
  end
end
