defmodule ExSaml.ErrorTest do
  use ExUnit.Case, async: false

  alias ExSaml.{Debug, Error, ErrorCache, StubCache}

  setup do
    StubCache.install()
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_saml_sub_status: nil, ex_saml_idp_id: nil, ex_saml_debug_id: nil)
    :ok
  end

  describe "new/1" do
    test "fills node, timestamp and leaves details nil when debug is off" do
      error = Error.new(%{reason: :bad_audience, step: :decode, idp_id: "acme", debug_id: "d1"})

      assert %Error{
               reason: :bad_audience,
               step: :decode,
               idp_id: "acme",
               debug_id: "d1",
               details: nil,
               saml_status: nil,
               saml_sub_status: nil
             } = error

      assert error.node == node()
      assert %DateTime{} = error.at
    end

    test "embeds the debug report when debug is on for the IdP" do
      Debug.enable(idp_id: "acme")
      Debug.capture("d1", :authn_request, %{relay_state: "d1"})

      error = Error.new(%{reason: :invalid_relay_state, idp_id: "acme", debug_id: "d1"})

      assert [{:authn_request, %{relay_state: "d1"}}] = error.details
    end

    test "resolves SAML status atoms for {:saml_error, _, _} reasons" do
      Logger.metadata(ex_saml_saml_sub_status: :authn_failed)

      error =
        Error.new(%{
          reason: {:saml_error, ~c"urn:oasis:names:tc:SAML:2.0:status:Responder", nil}
        })

      assert error.saml_status == :responder
      assert error.saml_sub_status == :authn_failed
    end
  end

  describe "issue/1 and get_from_id/1" do
    test "round-trips once, then the id is gone (single use)" do
      {error_id, %Error{} = issued} =
        %{reason: :bad_recipient, step: :decode, idp_id: "acme"} |> Error.new() |> Error.issue()

      assert is_binary(error_id)
      assert ErrorCache.ttl(error_id) == ErrorCache.ttl()

      assert {:ok, ^issued} = Error.get_from_id(error_id)
      assert {:error, :not_found} = Error.get_from_id(error_id)
    end

    test "unknown or malformed ids" do
      assert {:error, :not_found} = Error.get_from_id("nope")
      assert {:error, :not_found} = Error.get_from_id(nil)
    end

    test "error_ttl config is honoured" do
      Application.put_env(:ex_saml, :error_ttl, 1234)
      on_exit(fn -> Application.delete_env(:ex_saml, :error_ttl) end)

      {error_id, _} = %{reason: :duplicate} |> Error.new() |> Error.issue()
      assert ErrorCache.ttl(error_id) == 1234
    end
  end

  describe "append_error_id/2" do
    test "adds the query param to a bare URL" do
      assert Error.append_error_id("https://app.example.com/callback", "abc") ==
               "https://app.example.com/callback?error_id=abc"
    end

    test "preserves an existing query string" do
      assert Error.append_error_id("/callback?foo=bar", "abc") ==
               "/callback?error_id=abc&foo=bar"
    end
  end

  # `append_error_id/2` delegates here, and the success path uses it for `code`,
  # so both halves of the callback contract survive a target URL that carries a
  # query of its own.
  describe "Helper.append_query_param/3" do
    test "adds the param to a bare URL" do
      assert ExSaml.Helper.append_query_param("https://app.example.com/cb", "code", "abc") ==
               "https://app.example.com/cb?code=abc"
    end

    test "preserves an existing query string instead of emitting a second ?" do
      url = ExSaml.Helper.append_query_param("https://app.example.com/cb?x=1", "code", "abc")

      refute url =~ ~r/\?.*\?/
      assert URI.decode_query(URI.parse(url).query) == %{"x" => "1", "code" => "abc"}
    end

    test "keeps the fragment" do
      assert ExSaml.Helper.append_query_param("/cb#section", "code", "abc") ==
               "/cb?code=abc#section"
    end
  end
end
