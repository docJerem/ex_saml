defmodule ExSaml.SPLogoutRedirectBindingTest do
  @moduledoc """
  End-to-end tests for single logout over the HTTP-Redirect binding
  (SAML 2.0 Bindings §3.4.4), routed through `ExSaml.SPRouter`:

  IdP-initiated `GET /logout/:idp_id` requests carry the LogoutRequest in the
  query string, signed via the SigAlg/Signature query parameters (the way
  Microsoft Entra ID delivers them). The HTTP-POST binding route must keep its
  existing behaviour.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn, only: [get_resp_header: 2]

  require Record

  alias ExSaml.{Assertion, IdpData, State, Subject}
  alias ExSaml.Core.{IdpMetadata, SpConfig}

  @idp_id "idp1"
  @nameid "user@example.com"
  @request_id "_logout_req_42"
  @logout_location "https://idp.example.com/slo"
  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  @success_status "urn:oasis:names:tc:SAML:2.0:status:Success"
  @denied_status "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

  setup do
    previous_idps = Application.get_env(:ex_saml, :identity_providers)
    previous_store = Application.get_env(:ex_saml, :state_store)

    State.init(ExSaml.State.ETS, table: :slo_redirect_binding_test)
    :ets.delete_all_objects(:slo_redirect_binding_test)

    Application.put_env(:ex_saml, :identity_providers, %{@idp_id => idp_data()})

    on_exit(fn ->
      if previous_idps do
        Application.put_env(:ex_saml, :identity_providers, previous_idps)
      else
        Application.delete_env(:ex_saml, :identity_providers)
      end

      if previous_store do
        Application.put_env(:ex_saml, :state_store, previous_store)
      else
        Application.delete_env(:ex_saml, :state_store)
      end
    end)

    :ok
  end

  # ---------------------------------------------------------------------------
  # Fixtures
  # ---------------------------------------------------------------------------

  defp idp_data(sp_overrides \\ []) do
    sp_config =
      struct!(
        %SpConfig{
          entity_id: ~c"https://sp.example.com",
          metadata_uri: "https://sp.example.com/sp/metadata/#{@idp_id}",
          consume_uri: "https://sp.example.com/sp/consume/#{@idp_id}",
          logout_uri: "https://sp.example.com/sp/logout/#{@idp_id}",
          sp_sign_requests: false,
          sp_sign_metadata: false
        },
        sp_overrides
      )

    %IdpData{
      id: @idp_id,
      certs: [test_cert_der()],
      use_redirect_for_req: true,
      sp_config: sp_config,
      idp_metadata: %IdpMetadata{
        entity_id: "https://idp.example.com",
        login_location: "https://idp.example.com/sso",
        logout_location: @logout_location
      }
    }
  end

  defp test_key do
    [entry] = "test/data/test.pem" |> File.read!() |> :public_key.pem_decode()

    case :public_key.pem_entry_decode(entry) do
      {:PrivateKeyInfo, _, _, key_der, _} -> :public_key.der_decode(:RSAPrivateKey, key_der)
      key when Record.is_record(key, :RSAPrivateKey) -> key
    end
  end

  defp test_cert_der do
    [{:Certificate, der, :not_encrypted}] =
      "test/data/test.crt" |> File.read!() |> :public_key.pem_decode()

    der
  end

  defp logout_request_payload do
    xml =
      ~s(<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
        ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{@request_id}" ) <>
        ~s(Version="2.0" IssueInstant="#{DateTime.to_iso8601(DateTime.utc_now())}">) <>
        ~s(<saml:Issuer>https://idp.example.com</saml:Issuer>) <>
        ~s(<saml:NameID>#{@nameid}</saml:NameID>) <>
        ~s(</samlp:LogoutRequest>)

    xml |> :zlib.zip() |> Base.encode64()
  end

  # Builds the signed query string the way an IdP does (§3.4.4.1): URL-encode
  # each part, concatenate in canonical order, sign, append the signature.
  defp signed_logout_query(opts \\ []) do
    relay_state = Keyword.get(opts, :relay_state, "entra_relay")

    query =
      "SAMLRequest=#{URI.encode_www_form(logout_request_payload())}" <>
        if(relay_state, do: "&RelayState=#{URI.encode_www_form(relay_state)}", else: "") <>
        "&SigAlg=#{URI.encode_www_form(@rsa_sha256)}"

    signature = :public_key.sign(query, :sha256, test_key())
    signed = query <> "&Signature=#{URI.encode_www_form(Base.encode64(signature))}"

    if Keyword.get(opts, :tamper, false) do
      String.replace(signed, "SAMLRequest=", "SAMLRequest=eJxLy0lMBwAD", global: false)
    else
      signed
    end
  end

  defp unsigned_logout_query do
    "SAMLRequest=#{URI.encode_www_form(logout_request_payload())}&RelayState=entra_relay"
  end

  defp put_active_assertion do
    notonorafter = DateTime.utc_now() |> DateTime.add(300) |> DateTime.to_iso8601()

    assertion = %Assertion{
      idp_id: @idp_id,
      subject: %Subject{name: @nameid, notonorafter: notonorafter}
    }

    State.put_assertion(conn(:get, "/"), {@idp_id, @nameid}, assertion)
  end

  defp active_assertion, do: State.get_assertion(conn(:get, "/"), {@idp_id, @nameid})

  defp call_get_logout(query) do
    :get
    |> conn("/logout/#{@idp_id}?#{query}")
    |> init_test_session(%{})
    |> ExSaml.SPRouter.call(ExSaml.SPRouter.init([]))
  end

  defp logout_response_from(conn) do
    assert conn.status == 302
    [location] = get_resp_header(conn, "location")
    assert String.starts_with?(location, @logout_location)

    query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    xml = query["SAMLResponse"] |> Base.decode64!() |> :zlib.unzip()
    {xml, query}
  end

  # ---------------------------------------------------------------------------
  # GET (HTTP-Redirect binding)
  # ---------------------------------------------------------------------------

  describe "GET /logout/:idp_id with a signed LogoutRequest" do
    test "destroys the assertion and answers Success with InResponseTo" do
      put_active_assertion()

      conn = call_get_logout(signed_logout_query())

      {xml, query} = logout_response_from(conn)
      assert xml =~ @success_status
      assert xml =~ ~s(InResponseTo="#{@request_id}")
      assert query["RelayState"] == "entra_relay"
      assert active_assertion() == nil
    end

    test "answers RequestDenied when no assertion is active" do
      conn = call_get_logout(signed_logout_query())

      {xml, _query} = logout_response_from(conn)
      assert xml =~ @denied_status
      assert xml =~ ~s(InResponseTo="#{@request_id}")
    end

    test "works without RelayState" do
      put_active_assertion()

      conn = call_get_logout(signed_logout_query(relay_state: nil))

      {xml, _query} = logout_response_from(conn)
      assert xml =~ @success_status
    end
  end

  describe "GET /logout/:idp_id signature rejection" do
    test "rejects an unsigned LogoutRequest and keeps the assertion" do
      put_active_assertion()

      conn = call_get_logout(unsigned_logout_query())

      assert conn.status == 403
      assert conn.resp_body == "invalid_request"
      assert %Assertion{} = active_assertion()
    end

    test "rejects a tampered LogoutRequest and keeps the assertion" do
      put_active_assertion()

      conn = call_get_logout(signed_logout_query(tamper: true))

      assert conn.status == 403
      assert %Assertion{} = active_assertion()
    end

    test "accepts an unsigned LogoutRequest when idp_signs_logout_requests is disabled" do
      Application.put_env(:ex_saml, :identity_providers, %{
        @idp_id => idp_data(idp_signs_logout_requests: false)
      })

      put_active_assertion()

      conn = call_get_logout(unsigned_logout_query())

      {xml, _query} = logout_response_from(conn)
      assert xml =~ @success_status
      assert active_assertion() == nil
    end
  end

  # ---------------------------------------------------------------------------
  # POST (HTTP-POST binding) - existing behaviour must be unchanged
  # ---------------------------------------------------------------------------

  describe "POST /logout/:idp_id" do
    test "still processes a LogoutRequest from body params" do
      Application.put_env(:ex_saml, :identity_providers, %{
        @idp_id => idp_data(idp_signs_logout_requests: false)
      })

      put_active_assertion()

      conn =
        :post
        |> conn("/logout/#{@idp_id}", %{
          "SAMLRequest" => logout_request_payload(),
          "RelayState" => "post_relay"
        })
        |> init_test_session(%{})
        |> ExSaml.SPRouter.call(ExSaml.SPRouter.init([]))

      {xml, query} = logout_response_from(conn)
      assert xml =~ @success_status
      assert query["RelayState"] == "post_relay"
      assert active_assertion() == nil
    end
  end
end
