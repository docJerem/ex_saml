defmodule ExSamlIdpDataTest do
  use ExUnit.Case
  import ExUnit.CaptureLog
  alias ExSaml.Core.Sp
  alias ExSaml.Core.Xml.SafeXml
  alias ExSaml.{IdpData, SpData}

  @sp_config1 %{
    id: "sp1",
    entity_id: "urn:test:sp1",
    certfile: "test/data/test.crt",
    keyfile: "test/data/test.pem"
  }

  @sp_config2 %{
    id: "sp2",
    certfile: "test/data/test.crt",
    keyfile: "test/data/test.pem"
  }

  @sp_config3 %{
    id: "sp3",
    keyfile: "test/data/test.pem"
  }

  @sp_config4 %{
    id: "sp4",
    certfile: "test/data/test.crt"
  }

  @sp_config5 %{
    id: "sp5"
  }

  @idp_config1 %{
    id: "idp1",
    sp_id: "sp1",
    base_url: "http://ExSaml.howto:4003/sso",
    metadata_file: "test/data/idp_metadata.xml"
  }

  @idp_config2 %{
    id: "idp2",
    sp_id: "sp2",
    base_url: "http://ExSaml.howto:4003/sso",
    metadata_file: "test/data/idp_metadata.xml"
  }

  setup context do
    sp_data1 = SpData.load_provider(@sp_config1)
    sp_data2 = SpData.load_provider(@sp_config2)
    sp_data3 = SpData.load_provider(@sp_config3)
    sp_data4 = SpData.load_provider(@sp_config4)
    sp_data5 = SpData.load_provider(@sp_config5)

    [
      sps: %{
        sp_data1.id => sp_data1,
        sp_data2.id => sp_data2,
        sp_data3.id => sp_data3,
        sp_data4.id => sp_data4,
        sp_data5.id => sp_data5
      }
    ]
    |> Enum.into(context)
  end

  test "valid-idp-config-1", %{sps: sps} do
    %IdpData{} = idp_data = IdpData.load_provider(@idp_config1, sps)
    assert idp_data.valid?
  end

  test "metadata is parsed through SafeXml: a DOCTYPE is rejected", %{sps: sps} do
    metadata =
      "test/data/idp_metadata.xml"
      |> File.read!()
      |> String.replace(
        ~r/^<\?xml[^>]*\?>/,
        ~s(<?xml version="1.0"?><!DOCTYPE md:EntityDescriptor>)
      )

    assert metadata =~ "<!DOCTYPE"

    assert_raise ExSaml.ConfigError, ~r/invalid_xml/, fn ->
      IdpData.load_provider(Map.put(@idp_config1, :metadata, metadata), sps)
    end
  end

  # verify defaults
  test "valid-idp-config-2", %{sps: sps} do
    %IdpData{} = idp_data = IdpData.load_provider(@idp_config1, sps)
    refute idp_data.use_redirect_for_req
    assert idp_data.sign_requests
    assert idp_data.sign_metadata
    assert idp_data.signed_assertion_in_resp
    refute idp_data.signed_envelopes_in_resp
  end

  test "valid-idp-config-3", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        use_redirect_for_req: false,
        sign_requests: true,
        sign_metadata: true,
        signed_assertion_in_resp: true,
        signed_envelopes_in_resp: true
      })

    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    refute idp_data.use_redirect_for_req
    assert idp_data.sign_requests
    assert idp_data.sign_metadata
    assert idp_data.signed_assertion_in_resp
    assert idp_data.signed_envelopes_in_resp
  end

  test "valid-idp-config-4", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        use_redirect_for_req: true,
        sign_requests: false,
        sign_metadata: false,
        signed_assertion_in_resp: false,
        signed_envelopes_in_resp: false
      })

    log =
      capture_log(fn ->
        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        assert idp_data.use_redirect_for_req
        refute idp_data.sign_requests
        refute idp_data.sign_metadata
        refute idp_data.signed_assertion_in_resp
        refute idp_data.signed_envelopes_in_resp
      end)

    assert log =~ "signed_assertion_in_resp and signed_envelopes_in_resp are both false"
  end

  test "an IdP that requires no signature on its responses is invalid", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{signed_assertion_in_resp: false, signed_envelopes_in_resp: false})

    log =
      capture_log(fn ->
        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        refute idp_data.valid?
        assert IdpData.load_providers([idp_config], sps) == %{}
      end)

    assert log =~ "Skipping identity provider: idp1"
  end

  test "an IdP that requires only the envelope signature is valid", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{signed_assertion_in_resp: false, signed_envelopes_in_resp: true})

    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?
    refute idp_data.sp_config.idp_signs_assertions
    assert idp_data.sp_config.idp_signs_envelopes
  end

  describe "provider_type keeps the configured signature requirements" do
    @unsigned_response """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
      <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
        <saml:Subject>
          <saml:NameID>user@example.com</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData Recipient="http://ExSaml.howto:4003/sso/sp/consume/idp1" NotOnOrAfter="2099-01-01T00:00:00Z"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
      </saml:Assertion>
    </samlp:Response>
    """

    defp unsigned_response do
      {:ok, xml} = SafeXml.scan(@unsigned_response)
      xml
    end

    for provider_type <- [:adfs, :ping_federate, :ping_one] do
      test "#{provider_type}: the default requires a signed assertion", %{sps: sps} do
        idp_config = Map.put(@idp_config1, :provider_type, unquote(provider_type))

        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        assert idp_data.valid?
        assert idp_data.signed_assertion_in_resp
        assert idp_data.sp_config.idp_signs_assertions

        assert {:error, {:assertion, {:error, :no_signature}}} =
                 Sp.validate_assertion(unsigned_response(), idp_data.sp_config)
      end

      test "#{provider_type}: a required envelope signature is kept", %{sps: sps} do
        idp_config =
          Map.merge(@idp_config1, %{
            provider_type: unquote(provider_type),
            signed_assertion_in_resp: false,
            signed_envelopes_in_resp: true
          })

        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        assert idp_data.valid?
        assert idp_data.sp_config.idp_signs_envelopes

        assert {:error, {:envelope, {:error, :no_signature}}} =
                 Sp.validate_assertion(unsigned_response(), idp_data.sp_config)
      end
    end

    test "adfs still forces its other options off", %{sps: sps} do
      idp_config =
        Map.merge(@idp_config1, %{
          sp_id: "sp5",
          provider_type: :adfs,
          use_redirect_for_req: true,
          sign_requests: true,
          sign_metadata: true
        })

      %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
      assert idp_data.valid?
      refute idp_data.use_redirect_for_req
      refute idp_data.sign_requests
      refute idp_data.sign_metadata
    end
  end

  test "RSA-1_5 key transport is refused unless the IdP allows it", %{sps: sps} do
    %IdpData{} = idp_data = IdpData.load_provider(@idp_config1, sps)
    refute idp_data.allow_rsa_1_5_key_transport
    refute idp_data.sp_config.allow_rsa_1_5_key_transport

    idp_config = Map.put(@idp_config1, :allow_rsa_1_5_key_transport, true)
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.allow_rsa_1_5_key_transport
    assert idp_data.sp_config.allow_rsa_1_5_key_transport
  end

  test "user_key_attribute is idp_user_id unless the IdP names another or nil", %{sps: sps} do
    assert IdpData.load_provider(@idp_config1, sps).user_key_attribute == "idp_user_id"

    idp_config = Map.put(@idp_config1, :user_key_attribute, "uid")
    assert IdpData.load_provider(idp_config, sps).user_key_attribute == "uid"

    idp_config = Map.put(@idp_config1, :user_key_attribute, nil)
    assert IdpData.load_provider(idp_config, sps).user_key_attribute == nil
  end

  test "user_key_attribute must be an attribute name or nil", %{sps: sps} do
    for attr <- ["", :uid, 42] do
      idp_config = Map.put(@idp_config1, :user_key_attribute, attr)
      assert_raise ExSaml.ConfigError, fn -> IdpData.load_provider(idp_config, sps) end
    end
  end

  test "valid-idp-config-5", %{sps: sps} do
    idp_config = %{@idp_config1 | base_url: nil}
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?
    assert idp_data.base_url == nil
  end

  test "valid-idp-config-7", %{sps: sps} do
    idp_config = %{@idp_config1 | metadata_file: "test/data/azure_fed_metadata.xml"}
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?
  end

  test "valid-idp-config-8", %{sps: sps} do
    idp_config = %{@idp_config1 | metadata_file: "test/data/onelogin_idp_metadata.xml"}
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?
  end

  test "valid-idp-config-9", %{sps: sps} do
    idp_config = %{@idp_config1 | metadata_file: "test/data/shibboleth_idp_metadata.xml"}
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?
  end

  test "valid-idp-config-10", %{sps: sps} do
    idp_config = %{@idp_config1 | metadata_file: "test/data/simplesaml_idp_metadata.xml"}
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?
  end

  test "valid-idp-config-11", %{sps: sps} do
    idp_config = %{@idp_config1 | metadata_file: "test/data/testshib_metadata.xml"}

    log =
      capture_log(fn ->
        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        assert idp_data.valid?
      end)

    assert log =~ "SLO Endpoint missing"
  end

  test "url-test-1", %{sps: sps} do
    idp_config = %{@idp_config1 | metadata_file: "test/data/shibboleth_idp_metadata.xml"}
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?

    %ExSaml.Core.IdpMetadata{
      login_location: sso_url,
      logout_location: slo_url
    } = idp_data.idp_metadata

    assert sso_url |> List.to_string() |> String.ends_with?("/SAML2/POST/SSO")
    assert slo_url |> List.to_string() |> String.ends_with?("/SAML2/POST/SLO")
  end

  test "url-test-2", %{sps: sps} do
    idp_config = %{@idp_config1 | metadata_file: "test/data/shibboleth_idp_metadata.xml"}
    idp_config = Map.put(idp_config, :use_redirect_for_req, true)
    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?

    %ExSaml.Core.IdpMetadata{
      login_location: sso_url,
      logout_location: slo_url
    } = idp_data.idp_metadata

    assert sso_url |> List.to_string() |> String.ends_with?("/SAML2/Redirect/SSO")
    assert slo_url |> List.to_string() |> String.ends_with?("/SAML2/Redirect/SLO")
  end

  test "sp entity_id test-1", %{sps: sps} do
    %IdpData{} = idp_data = IdpData.load_provider(@idp_config2, sps)
    assert idp_data.valid?
    %ExSaml.Core.SpConfig{entity_id: entity_id} = idp_data.sp_config
    assert entity_id == nil
  end

  test "invalid-idp-config-1", %{sps: sps} do
    idp_config = %{@idp_config1 | id: ""}

    log =
      capture_log(fn ->
        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        refute idp_data.valid?
      end)

    assert log =~ "Invalid IdP Config"
  end

  test "invalid-idp-config-2", %{sps: sps} do
    idp_config = %{@idp_config1 | sp_id: "unknown-sp"}

    log =
      capture_log(fn ->
        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        refute idp_data.valid?
      end)

    assert log =~ "Unknown/invalid sp_id"
  end

  test "valid-idp-config-signing-turned-off", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        sp_id: "sp5",
        use_redirect_for_req: true,
        sign_requests: false,
        sign_metadata: false
      })

    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.valid?
  end

  test "invalid-idp-config-signing-on-cert-missing", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        sp_id: "sp3",
        use_redirect_for_req: true,
        sign_requests: true,
        sign_metadata: false
      })

    log =
      capture_log(fn ->
        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        refute idp_data.valid?
      end)

    assert log =~ "SP cert or key missing"
  end

  test "invalid-idp-config-signing-on-key-missing", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        sp_id: "sp4",
        use_redirect_for_req: true,
        sign_requests: true,
        sign_metadata: false
      })

    log =
      capture_log(fn ->
        %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
        refute idp_data.valid?
      end)

    assert log =~ "SP cert or key missing"
  end

  test "nameid-format-in-metadata-but-not-config-should-use-metadata", %{sps: sps} do
    %IdpData{} = idp_data = IdpData.load_provider(@idp_config1, sps)
    assert idp_data.nameid_format == ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  end

  test "nameid-format-in-config-but-not-metadata-should-use-config", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        metadata_file: "test/data/shibboleth_idp_metadata.xml",
        nameid_format: :email
      })

    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.nameid_format == ~c"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  end

  test "nameid-format-in-metadata-and-config-should-use-config", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        nameid_format: :persistent
      })

    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.nameid_format == ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  end

  test "nameid-format-in-neither-metadata-nor-config-should-be-unknown", %{sps: sps} do
    idp_config =
      Map.merge(@idp_config1, %{
        metadata_file: "test/data/shibboleth_idp_metadata.xml"
      })

    %IdpData{} = idp_data = IdpData.load_provider(idp_config, sps)
    assert idp_data.nameid_format == :unknown
  end
end
