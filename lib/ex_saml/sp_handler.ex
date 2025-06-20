defmodule ExSaml.SPHandler do
  @moduledoc false

  require Logger
  import Plug.Conn
  # alias Plug.Conn
  require ExSaml.Esaml

  alias ExSaml.{
    Assertion,
    Esaml,
    Helper,
    IdpData,
    State,
    RelayStateCache,
    Subject
  }

  import ExSaml.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 5, redirect: 3]

  # sobelow_skip ["XSS.SendResp"]
  def send_metadata(conn) do
    %IdpData{} = idp = conn.private[:ex_saml_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)
    metadata = Helper.sp_metadata(sp)

    conn
    |> put_resp_header("content-type", "text/xml")
    |> send_resp(200, metadata)

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  @doc "After the AuthHandler.send_signin_req, receive the response from the IDP"
  def consume_signin_response(conn, %IdpData{id: idp_id, esaml_sp_rec: sp_rec} = idp_data) do
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]

    rls = conn.body_params["RelayState"] || Map.get(conn.params, "RelayState")
    relay_state = safe_decode_www_form(rls)
    user_token = RelayStateCache.get(relay_state)[:user_token]
    redirect_uri = RelayStateCache.get(relay_state)[:redirect_uri]

    with :ok <- maybe_redirect_to_start_url(conn, rls),
         {:ok, assertion} <- Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response),
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

  defp maybe_redirect_to_start_url(conn, rls) do
    if String.contains?(rls, "https://start-from:") do
      {:halted, redirect(conn, 302, String.replace(rls, "start-from:", ""))}
    else
      :ok
    end
  end

  # IDP-initiated flow auth response
  defp validate_authresp(_conn, idp_data, %{subject: %{in_response_to: ""}}, relay_state) do
    if idp_data.allow_idp_initiated_flow do
      if idp_data.allowed_target_urls do
        if relay_state in idp_data.allowed_target_urls do
          :ok
        else
          {:error, :invalid_target_url}
        end
      else
        :ok
      end
    else
      {:error, :idp_first_flow_not_allowed}
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

  # sobelow_skip ["XSS.SendResp"]
  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

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
      error -> conn |> send_resp(403, "invalid_request #{inspect(error)}")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # non-ui logout request from IDP
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_request = conn.body_params["SAMLRequest"]
    rls = conn.body_params["RelayState"]
    relay_state = safe_decode_www_form(rls)

    with {:ok, payload} <- Helper.decode_idp_signout_req(sp, saml_encoding, saml_request) do
      Esaml.esaml_logoutreq(name: nameid, issuer: _issuer) = payload
      assertion_key = {idp_id, nameid}

      {conn, return_status} =
        case State.get_assertion(conn, assertion_key) do
          %Assertion{idp_id: ^idp_id, subject: %Subject{name: ^nameid}} ->
            conn = State.delete_assertion(conn, assertion_key)
            {conn, :success}

          _ ->
            {conn, :denied}
        end

      {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, return_status)

      conn
      |> configure_session(drop: true)
      |> send_saml_request(idp_signout_url, idp.use_redirect_for_req, resp_xml_frag, relay_state)
    else
      error ->
        Logger.error("#{inspect(error)}")
        {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, :denied)

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

  def target_url(conn, relay_state) do
    get_session(conn, "target_url") || RelayStateCache.get(relay_state)[:target_url]
  end

  def target_url, do: Application.get_env(:ex_saml, :fallback_target_url, "/")

  defp safe_decode_www_form(nil), do: ""
  defp safe_decode_www_form(data), do: URI.decode_www_form(data)
end
