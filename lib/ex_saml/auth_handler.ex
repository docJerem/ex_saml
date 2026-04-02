defmodule ExSaml.AuthHandler do
  @moduledoc """
  Handles SAML authentication requests (sign-in and sign-out) with the Identity Provider.

  ## Functions

    * `request_idp/2` - Initiates a full SAML SSO request to a specific IdP
    * `send_signin_req/1` - Sends a sign-in request using the IdP from `conn.private[:ex_saml_idp]`
    * `send_signout_req/1` - Sends a sign-out request for the current session
  """

  require Logger
  import Plug.Conn
  alias ExSaml.{Assertion, Helper, IdpData, RelayStateCache, State, Subject}

  import ExSaml.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 6, redirect: 3]

  @relay_state_cache_ttl :timer.minutes(5)

  @doc """
  Handles the full SAML request to the IdP without requiring an intermediate HTML form.
  Can be called directly in a Phoenix controller action.

  You do not need to call initiate_sso_req, then send_signin_req: the full processus is
  done.
  """
  def request_idp(conn, idp_id) do
    conn = put_private(conn, :ex_saml_idp, ExSaml.Helper.get_idp(idp_id))

    %IdpData{id: ^idp_id, esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} =
      idp = conn.private[:ex_saml_idp]

    sp = ensure_sp_uris_set(sp_rec, conn)
    assertion_key = get_session(conn, "ex_saml_assertion_key")
    relay_state = State.gen_id()
    session_id = get_session(conn, :session_id)

    RelayStateCache.put(
      relay_state,
      %{
        relay_state: relay_state,
        session_id: session_id,
        saml_nonce:
          fetch_cookies(conn, encrypted: ~w(saml_nonce)).cookies["saml_nonce"] || UUID.uuid4(),
        idp_id: idp_id,
        user_token: get_session(conn, :user_token),
        redirect_uri: get_session(conn, :redirect_uri)
        # target_url: target_url
      },
      ttl: @relay_state_cache_ttl
    )

    {idp_signin_url, req_xml_frag} =
      Helper.gen_idp_signin_req(sp, idp_rec, Map.get(idp, :nameid_format))

    conn
    |> State.delete_assertion(assertion_key)
    # NOTE: conflict with the current Gateway User session ?
    # # if yes then we need to add an option to put back the user token session
    |> configure_session(renew: true)
    |> put_session("relay_state", relay_state)
    |> put_session("idp_id", idp_id)
    # |> put_session("target_url", target_url)
    #
    |> send_saml_request(
      idp_signin_url,
      idp.use_redirect_for_req,
      req_xml_frag,
      relay_state,
      idp.remove_saml_encoding
    )
  end

  @doc """
  Sends a SAML sign-in request to the IdP.

  Expects `conn.private[:ex_saml_idp]` and `conn.private[:ex_saml_target_url]` to be set.
  If the user already has a valid assertion for this IdP, redirects to the target URL.
  """
  def send_signin_req(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    target_url = conn.private[:ex_saml_target_url] || "/"
    assertion_key = get_session(conn, "ex_saml_assertion_key")

    case State.get_assertion(conn, assertion_key) do
      %Assertion{idp_id: ^idp_id} ->
        conn |> redirect(302, target_url)

      _ ->
        relay_state = State.gen_id()

        session_id = get_session(conn, :session_id)

        RelayStateCache.put(
          relay_state,
          %{
            relay_state: relay_state,
            session_id: session_id,
            saml_nonce:
              fetch_cookies(conn, encrypted: ~w(saml_nonce)).cookies["saml_nonce"] || UUID.uuid4(),
            idp_id: idp_id,
            target_url: target_url,
            user_token: get_session(conn, :user_token),
            redirect_uri: get_session(conn, :redirect_uri)
          },
          ttl: @relay_state_cache_ttl
        )

        {idp_signin_url, req_xml_frag} =
          Helper.gen_idp_signin_req(sp, idp_rec, Map.get(idp, :nameid_format))

        conn
        |> State.delete_assertion(assertion_key)
        |> configure_session(renew: true)
        |> put_session("relay_state", relay_state)
        |> put_session("idp_id", idp_id)
        |> put_session("target_url", target_url)
        |> send_saml_request(
          idp_signin_url,
          idp.use_redirect_for_req,
          req_xml_frag,
          relay_state,
          idp.remove_saml_encoding
        )
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  @doc """
  Sends a SAML sign-out request to the IdP.

  Expects `conn.private[:ex_saml_idp]` to be set. Requires an active assertion
  for the current IdP, otherwise returns 403.
  """
  def send_signout_req(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:ex_saml_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    target_url = conn.private[:ex_saml_target_url] || "/"
    assertion_key = get_session(conn, "ex_saml_assertion_key")

    case State.get_assertion(conn, assertion_key) do
      %Assertion{idp_id: ^idp_id, authn: authn, subject: subject} ->
        session_index = Map.get(authn, "session_index", "")
        subject_rec = Subject.to_rec(subject)

        {idp_signout_url, req_xml_frag} =
          Helper.gen_idp_signout_req(sp, idp_rec, subject_rec, session_index)

        conn = State.delete_assertion(conn, assertion_key)
        relay_state = State.gen_id()

        conn
        |> put_session("target_url", target_url)
        |> put_session("relay_state", relay_state)
        |> put_session("idp_id", idp_id)
        |> delete_session("ex_saml_assertion_key")
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          req_xml_frag,
          relay_state,
          idp.remove_saml_encoding
        )

      _ ->
        conn |> send_resp(403, "access_denied")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end
end
