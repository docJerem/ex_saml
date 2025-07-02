defmodule ExSaml.Router do
  @moduledoc false

  use Plug.Router

  plug(ExSaml.SecurityPlug)
  plug(:match)
  plug(:dispatch)

  forward("/auth", to: ExSaml.AuthRouter)
  forward("/csp-report", to: ExSaml.CsprRouter)

  match _ do
    conn |> send_resp(404, "not_found")
  end
end
