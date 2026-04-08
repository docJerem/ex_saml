defmodule ExSaml.Router do
  @moduledoc """
  Main SAML router. Forward this in your Phoenix router:

      forward "/sso", ExSaml.Router

  Routes:
    * `/auth/signin/*idp_id` - Initiate sign-in (POST)
    * `/auth/signout/*idp_id` - Initiate sign-out (POST)
    * `/csp-report` - CSP violation report endpoint
  """

  use Plug.Router

  plug(ExSaml.SecurityPlug)
  plug(:match)
  plug(:dispatch)

  forward("/auth", to: ExSaml.AuthRouter)
  forward("/csp-report", to: ExSaml.CsprRouter)
  forward("/sp", to: ExSaml.SPRouter)

  match _ do
    conn |> send_resp(404, "not_found")
  end
end
