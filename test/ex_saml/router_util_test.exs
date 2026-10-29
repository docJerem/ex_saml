defmodule ExSaml.RouterUtilTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias ExSaml.{IdpData, RouterUtil}

  defp signin_conn(params, idp \\ nil) do
    conn = conn(:post, "/sso/auth/signin/acme", params)
    if idp, do: put_private(conn, :ex_saml_idp, idp), else: conn
  end

  describe "check_target_url/2" do
    test "keeps a relative path" do
      conn = RouterUtil.check_target_url(signin_conn(%{"target_url" => "%2Fcallback"}), [])

      refute conn.halted
      assert conn.private[:ex_saml_target_url] == "/callback"
    end

    test "keeps a path with a query" do
      conn =
        RouterUtil.check_target_url(signin_conn(%{"target_url" => "%2F%3Fidp_id%3Dacme"}), [])

      refute conn.halted
      assert conn.private[:ex_saml_target_url] == "/?idp_id=acme"
    end

    test "is nil without the parameter" do
      conn = RouterUtil.check_target_url(signin_conn(%{}), [])

      refute conn.halted
      assert conn.private[:ex_saml_target_url] == nil
    end

    test "keeps an absolute URL listed in the IdP's allowed_target_urls" do
      idp = %IdpData{id: "acme", allowed_target_urls: ["https://app.example.com/cb"]}

      conn =
        RouterUtil.check_target_url(
          signin_conn(%{"target_url" => "https://app.example.com/cb"}, idp),
          []
        )

      refute conn.halted
      assert conn.private[:ex_saml_target_url] == "https://app.example.com/cb"
    end

    for url <- [
          "https://elsewhere.example.com/",
          "//elsewhere.example.com/",
          "/\\elsewhere.example.com",
          "javascript:alert(1)"
        ] do
      test "answers 400 to #{inspect(url)}" do
        idp = %IdpData{id: "acme", allowed_target_urls: ["https://app.example.com/cb"]}

        log =
          capture_log(fn ->
            conn =
              RouterUtil.check_target_url(signin_conn(%{"target_url" => unquote(url)}, idp), [])

            assert conn.halted
            assert conn.status == 400
            assert conn.resp_body == "invalid target_url"
          end)

        assert log =~ "target_url must be a relative path or one of allowed_target_urls"
      end
    end

    test "answers 400 to an absolute URL when the IdP is unknown" do
      {conn, _log} =
        with_log(fn ->
          RouterUtil.check_target_url(
            signin_conn(%{"target_url" => "https://app.example.com/cb"}),
            []
          )
        end)

      assert conn.halted
      assert conn.status == 400
    end
  end

  describe "relative_path?/1" do
    test "accepts a path on this host" do
      assert RouterUtil.relative_path?("/")
      assert RouterUtil.relative_path?("/dashboard?x=1#top")
    end

    test "rejects anything a browser could read as another origin" do
      refute RouterUtil.relative_path?("https://elsewhere.example.com/")
      refute RouterUtil.relative_path?("//elsewhere.example.com/")
      refute RouterUtil.relative_path?("/\\elsewhere.example.com")
      refute RouterUtil.relative_path?("/\telsewhere.example.com")
      refute RouterUtil.relative_path?("elsewhere.example.com")
      refute RouterUtil.relative_path?(nil)
    end
  end
end
