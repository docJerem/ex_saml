defmodule ExSaml.AuthHandler do
  @moduledoc false

  require Logger
  import Plug.Conn
  alias ExSaml.{Assertion, IdpData, Helper, State, RelayStateCache, Subject}

  import ExSaml.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 6, redirect: 3]

  @sso_init_resp_template """
  <!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"
    \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">
  <html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
    <head>
      <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>
    </head>
    <body>
      <script nonce=\"<%= nonce %>\">
        document.addEventListener(\"DOMContentLoaded\", function () {
          document.getElementById(\"sso-req-form\").submit();
        });
      </script>
      <noscript>
        <p><strong>Note:</strong>
          Since your browser does not support JavaScript, you must press
          the button below to proceed.
        </p>
      </noscript>
      <form id=\"sso-req-form\" method=\"post\" action=\"<%= action %>\">
        <%= if target_url do %>
        <input type=\"hidden\" name=\"target_url\" value=\"<%= target_url %>\" />
        <% end %>
        <input type=\"hidden\" name=\"_csrf_token\" value=\"<%= csrf_token %>\" />
        <noscript><input type=\"submit\" value=\"Submit\" /></noscript>
      </form>
    </body>
  </html>
  """

  @doc "Prepare the request before to start send_signin_req"
  # sobelow_skip ["XSS.SendResp"]
  def initiate_sso_req(conn) do
    import Plug.CSRFProtection, only: [get_csrf_token: 0]

    target_url = conn.private[:ex_saml_target_url] || "/"

    opts = [
      nonce: conn.private[:ex_saml_nonce],
      action: URI.encode(conn.request_path),
      target_url: URI.encode_www_form(target_url),
      csrf_token: get_csrf_token()
    ]

    conn
    |> put_resp_header("content-type", "text/html")
    |> send_resp(200, EEx.eval_string(@sso_init_resp_template, opts))
  end

  @doc """
  Handles the full SAML request to the IdP without requiring an intermediate HTML form.
  Can be called directly in a Phoenix controller action.

  You do not need to call initiate_sso_req, then send_signin_req: the full processus is
  done.
  """
  def request_idp(conn, idp_id) do
    conn =
      conn
      |> put_private(:ex_saml_nonce, :crypto.strong_rand_bytes(18) |> Base.encode64())
      |> put_private(:ex_saml_idp, ExSaml.Helper.get_idp(idp_id))

    %IdpData{id: ^idp_id, esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} =
      idp = Helper.get_idp(idp_id)

    sp = ensure_sp_uris_set(sp_rec, conn)
    assertion_key = get_session(conn, "ex_saml_assertion_key")
    relay_state = State.gen_id()
    session_id = get_session(conn, :session_id)

    RelayStateCache.put(
      relay_state,
      %{
        relay_state: relay_state,
        session_id: session_id,
        # TODO: Audit the nonce
        saml_nonce:
          fetch_cookies(conn, encrypted: ~w(saml_nonce)).cookies["saml_nonce"] || UUID.uuid4(),
        idp_id: idp_id,
        user_token: get_session(conn, :user_token),
        redirect_uri: get_session(conn, :redirect_uri)
        # target_url: target_url
      },
      ttl: RelayStateCache.ttl()
    )

    {idp_signin_url, req_xml_frag} =
      Helper.gen_idp_signin_req(sp, idp_rec, Map.get(idp, :nameid_format))

    conn
    |> State.delete_assertion(assertion_key)
    # NOTE: conflict with the current Gateway User session ?
    # # if yes then we need to add an option to put back the user token session
    |> configure_session(renew: true)

    # TODO: The following session elements has currently no TTL
    # NOTE: We need to audit
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

  @doc "Run the request to the Identity Provider"
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
          ttl: RelayStateCache.ttl()
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
