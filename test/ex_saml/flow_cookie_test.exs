defmodule ExSaml.FlowCookieTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias ExSaml.FlowCookie

  defp cookie(conn), do: conn.resp_cookies[FlowCookie.name()]

  test "over HTTPS the cookie is SameSite=None and Secure, so the IdP's cross-site POST carries it" do
    conn = :get |> conn("https://sp.example.com/sso/auth/acme") |> FlowCookie.put("rs-1", 300)

    assert %{value: "rs-1", same_site: "None", secure: true, http_only: true, max_age: 300} =
             cookie(conn)
  end

  test "behind a proxy that forwards x-forwarded-proto: https, the same" do
    conn =
      :get
      |> conn("/sso/auth/acme")
      |> put_req_header("x-forwarded-proto", "https")
      |> FlowCookie.put("rs-1", 300)

    assert %{value: "rs-1", same_site: "None", secure: true} = cookie(conn)
  end

  test "over plain HTTP the SameSite attribute is left to the browser" do
    conn = :get |> conn("/sso/auth/acme") |> FlowCookie.put("rs-1", 300)

    assert %{value: "rs-1", http_only: true} = cookie = cookie(conn)
    refute Map.has_key?(cookie, :same_site)
    refute Map.get(cookie, :secure)
  end

  test "get/1 reads the relay state the browser sent, nil without one" do
    assert :get |> conn("/") |> FlowCookie.get() == nil

    assert :get |> conn("/") |> put_req_cookie(FlowCookie.name(), "rs-1") |> FlowCookie.get() ==
             "rs-1"
  end

  test "delete/1 expires it" do
    conn = :get |> conn("/") |> FlowCookie.delete()
    assert %{max_age: 0} = cookie(conn)
  end
end
