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

  Returns `{:ok, %{assertion: assertion, nonce: nonce, user_token: token, redirect_uri: uri}}`
  on success, or `{:error, reason}` on failure.
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
         {:ok, nonce} <- validate_authresp(conn, idp_data, assertion, relay_state) do
      {:ok,
       %{
         assertion: %Assertion{assertion | idp_id: idp_id},
         nonce: nonce,
         user_token: user_token,
         redirect_uri: redirect_uri
       }}
    else
      {:error, error} -> {:error, error}
      _ -> {:error, :access_denied}
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

  # IDP-initiated flow auth response
  defp validate_authresp(_conn, idp_data, %{subject: %{in_response_to: ""}}, relay_state) do
    cond do
      !idp_data.allow_idp_initiated_flow ->
        {:error, :idp_first_flow_not_allowed}

      idp_data.allowed_target_urls && relay_state not in idp_data.allowed_target_urls ->
        {:error, :invalid_target_url}

      true ->
        :ok
    end
  end

  # SP-initiated flow auth response
  defp validate_authresp(conn, %IdpData{id: idp_id}, _assertion, relay_state) do
    rs_in_session =
      get_session(conn, "relay_state") || RelayStateCache.get(relay_state)[:relay_state]

    idp_id_in_session = get_session(conn, "idp_id") || RelayStateCache.get(relay_state)[:idp_id]

    saml_nonce_in_session =
      get_session(conn, "saml_nonce") || RelayStateCache.get(relay_state)[:saml_nonce]

    # RelayStateCache.delete(relay_state)

    cond do
      rs_in_session == nil || rs_in_session != relay_state ->
        {:error, :invalid_relay_state}

      idp_id_in_session == nil || idp_id_in_session != idp_id ->
        {:error, :invalid_idp_id}

      true ->
        {:ok, saml_nonce_in_session}
    end
  end

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

  @doc "Returns the target URL from session or relay state cache."
  def target_url(conn, relay_state) do
    get_session(conn, "target_url") || RelayStateCache.get(relay_state)[:target_url]
  end

  @doc "Returns the fallback target URL from application config (defaults to `\"/\"`)."
  def target_url, do: Application.get_env(:ex_saml, :fallback_target_url, "/")

  defp safe_decode_www_form(nil), do: ""
  defp safe_decode_www_form(data), do: URI.decode_www_form(data)
end
