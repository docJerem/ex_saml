defmodule ExSaml.SPRouter do
  @moduledoc false

  use Plug.Router
  import ExSaml.RouterUtil, only: [check_idp_id: 2]
  import Plug.Conn

  plug(:fetch_session)
  # Redirect binding messages (GET /logout) arrive in the query string;
  # Plug.Router does not fetch query params on its own. No-op when the host
  # framework already fetched them.
  plug(:fetch_query_params)
  plug(:match)
  plug(:check_idp_id)
  plug(:dispatch)

  get("/metadata/:idp_id", do: ExSaml.SPHandler.send_metadata(conn))

  post("/consume/:idp_id", do: ExSaml.SPHandler.consume_signin_response(conn))

  post "/logout/:idp_id" do
    cond do
      conn.params["SAMLResponse"] -> ExSaml.SPHandler.handle_logout_response(conn)
      conn.params["SAMLRequest"] -> ExSaml.SPHandler.handle_logout_request(conn)
      true -> send_resp(conn, 403, "invalid_request")
    end
  end

  # HTTP-Redirect binding (SAML 2.0 Bindings §3.4.4). Microsoft Entra ID and
  # other IdPs deliver IdP-initiated single-logout requests as a GET with the
  # message in the query string, signed via the SigAlg/Signature parameters.
  get "/logout/:idp_id" do
    cond do
      conn.params["SAMLResponse"] -> ExSaml.SPHandler.handle_logout_response(conn)
      conn.params["SAMLRequest"] -> ExSaml.SPHandler.handle_logout_request(conn)
      true -> send_resp(conn, 403, "invalid_request")
    end
  end

  match(_, do: send_resp(conn, 404, "not_found"))
end
