defmodule ExSaml.FlowCookie do
  @moduledoc """
  The cookie that binds a SAML response to the browser that started the flow.

  `ExSaml.AuthHandler` sets it, holding the relay state of the AuthnRequest,
  when it sends the browser to the IdP. The IdP posts the response back from
  its own origin, a cross-site request on which browsers withhold a session
  cookie marked `SameSite=Lax` (the usual setting): the session may then be
  empty on the assertion consumer service, and the relay state cache alone
  cannot tell the browser that started the flow from any other. This cookie
  can, and `ExSaml.SPHandler` requires it to name the posted `RelayState`
  whenever the session does not. Without it, a response an attacker obtained
  for their own account could be posted in a victim's browser and sign the
  victim in as the attacker (login CSRF).

  The cookie is sent on that cross-site POST only with `SameSite=None`, which
  browsers accept only together with `Secure`, so it is set that way when the
  request came over HTTPS, directly or through a proxy that forwards
  `x-forwarded-proto: https`. Over plain HTTP, in development, the attribute
  is left to the browser's default.
  """

  import Plug.Conn

  @name "_ex_saml_flow"

  @doc "The cookie name."
  @spec name() :: String.t()
  def name, do: @name

  @doc """
  Sets the cookie to `relay_state` for `max_age` seconds, the lifetime of the
  relay state.
  """
  @spec put(Plug.Conn.t(), String.t(), non_neg_integer()) :: Plug.Conn.t()
  def put(conn, relay_state, max_age) when is_binary(relay_state) do
    opts = [max_age: max_age, http_only: true, path: "/"] ++ same_site(conn)
    put_resp_cookie(conn, @name, relay_state, opts)
  end

  @doc "The relay state the browser's cookie names, `nil` without one."
  @spec get(Plug.Conn.t()) :: String.t() | nil
  def get(conn), do: fetch_cookies(conn).req_cookies[@name]

  @doc "Expires the cookie."
  @spec delete(Plug.Conn.t()) :: Plug.Conn.t()
  def delete(conn), do: delete_resp_cookie(conn, @name, path: "/")

  defp same_site(conn) do
    if https?(conn), do: [same_site: "None", secure: true], else: []
  end

  defp https?(%Plug.Conn{scheme: :https}), do: true
  defp https?(conn), do: get_req_header(conn, "x-forwarded-proto") == ["https"]
end
