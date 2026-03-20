defmodule ExSaml.SecurityPlug do
  @moduledoc """
  Plug that sets security headers on SAML responses.

  Applied automatically by `ExSaml.Router`. Sets the following headers:
    * `content-security-policy` - with a per-request nonce (available via `conn.private[:ex_saml_nonce]`)
    * `cache-control` / `pragma` - no caching
    * `x-frame-options` - SAMEORIGIN
    * `x-xss-protection` - enabled with block mode
    * `x-content-type-options` - nosniff
  """

  import Plug.Conn
  alias Plug.Conn

  @csp """
       default-src 'none';
       script-src 'self' 'nonce-<%= nonce %>' 'report-sample';
       img-src 'self' 'report-sample';
       report-to /sso/csp-report;
       """
       |> String.replace("\n", " ")

  @doc false
  @spec init(Plug.opts()) :: Plug.opts()
  def init(opts), do: opts

  @spec call(Conn.t(), Plug.opts()) :: Conn.t()
  def call(%Conn{} = conn, _opts) do
    conn
    |> put_private(:ex_saml_nonce, :crypto.strong_rand_bytes(18) |> Base.encode64())
    |> register_before_send(fn connection ->
      nonce = connection.private[:ex_saml_nonce]

      connection
      |> put_resp_header("cache-control", "no-cache, no-store, must-revalidate")
      |> put_resp_header("pragma", "no-cache")
      |> put_resp_header("x-frame-options", "SAMEORIGIN")
      |> put_resp_header("content-security-policy", EEx.eval_string(@csp, nonce: nonce))
      |> put_resp_header("x-xss-protection", "1; mode=block")
      |> put_resp_header("x-content-type-options", "nosniff")
    end)
  end
end
