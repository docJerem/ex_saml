defmodule ExSaml.Core.SpLogoutResponseTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.{Sp, SpConfig}
  alias ExSaml.Core.Xml.{Dsig, SafeXml}
  alias ExSaml.SpData

  @logout_uri "https://sp.example.com/sso/logout/acme"

  setup_all do
    sp_data =
      SpData.load_provider(%SpData{
        id: "sp1",
        certfile: "test/data/test.crt",
        keyfile: "test/data/test.pem"
      })

    %{key: sp_data.key, cert: sp_data.cert}
  end

  defp sp(cert, overrides) do
    struct!(
      %SpConfig{
        logout_uri: @logout_uri,
        trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}]
      },
      overrides
    )
  end

  defp logout_response do
    {:ok, xml} =
      SafeXml.scan("""
      <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lr1" Version="2.0"
        IssueInstant="2026-01-01T00:00:00Z" Destination="#{@logout_uri}" InResponseTo="_req1">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      </samlp:LogoutResponse>
      """)

    xml
  end

  defp signed_logout_response(key, cert), do: Dsig.sign(logout_response(), key, cert, :rsa_sha256)

  describe "validate_logout_response/2" do
    test "accepts a LogoutResponse signed by the IdP", %{key: key, cert: cert} do
      assert {:ok, %{status: :success}} =
               Sp.validate_logout_response(signed_logout_response(key, cert), sp(cert, []))
    end

    test "rejects an unsigned LogoutResponse by default", %{cert: cert} do
      assert {:error, :no_signature} =
               Sp.validate_logout_response(logout_response(), sp(cert, []))
    end

    test "accepts an unsigned LogoutResponse when the IdP does not sign them", %{cert: cert} do
      assert {:ok, %{status: :success}} =
               Sp.validate_logout_response(
                 logout_response(),
                 sp(cert, idp_signs_logout_responses: false)
               )
    end

    test "still verifies a signature that is present when the IdP does not sign them", %{
      key: key,
      cert: cert
    } do
      sp =
        sp(cert, idp_signs_logout_responses: false, trusted_fingerprints: [{:sha256, <<0::256>>}])

      assert {:error, :cert_not_accepted} =
               Sp.validate_logout_response(signed_logout_response(key, cert), sp)
    end
  end
end
