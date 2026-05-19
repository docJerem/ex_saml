defmodule ExSaml.MetadataTest do
  use ExUnit.Case, async: true

  alias ExSaml.Metadata
  alias ExSaml.Metadata.ValidationResult
  alias ExSaml.Test.CertFactory

  @fixtures_dir Path.expand("../fixtures/metadata", __DIR__)

  defp read_fixture(name), do: File.read!(Path.join(@fixtures_dir, name))

  defp codes(violations), do: Enum.map(violations, & &1.code)

  defp sp_metadata_with_keys(key_descriptors) do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         entityID="https://sp.example.com/saml">
      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        #{Enum.join(key_descriptors, "\n    ")}
        <md:AssertionConsumerService index="0" isDefault="true"
                                     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="https://sp.example.com/saml/acs"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>
    """
  end

  defp key_descriptor(use, b64) do
    """
    <md:KeyDescriptor use="#{use}">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>#{b64}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
    """
  end

  describe "validate/1 happy path" do
    test "returns :ok on spec-clean SP metadata" do
      xml = read_fixture("sp_clean.xml")

      assert {:ok, %ValidationResult{errors: [], warnings: []}} = Metadata.validate(xml)
    end

    test "returns :ok on spec-clean IdP metadata" do
      xml = read_fixture("idp_clean.xml")

      assert {:ok, %ValidationResult{errors: [], warnings: []}} = Metadata.validate(xml)
    end
  end

  describe "XML well-formedness" do
    test "flags malformed XML with :invalid_xml" do
      xml = read_fixture("invalid_xml.xml")

      assert {:error, %ValidationResult{errors: [err]}} = Metadata.validate(xml)
      assert err.code == :invalid_xml
      assert err.severity == :error
      assert err.path == nil
    end

    test "flags empty binary as :invalid_xml" do
      assert {:error, %ValidationResult{errors: [%{code: :invalid_xml}]}} =
               Metadata.validate("")
    end

    # Regression: parse/1 used to call String.to_charlist on the raw UTF-8
    # binary, producing a list of codepoints. xmerl_scan expects raw UTF-8
    # bytes and crashed with {:wfc_Legal_Character, {:bad_character, _}} on
    # any non-ASCII character (e.g. an Organization name with an accent).
    for {label, sample} <- [
          {"latin-1 supplement (é)", "Société Élysée SAS"},
          {"german umlaut (ü/ß)", "Müller Straße GmbH"},
          {"polish (Ł)", "Łukasz Sp. z o.o."},
          {"euro sign (€)", "10€ Org"},
          {"greek (Ω)", "ΩΑΘ Foundation"},
          {"cyrillic", "Иван Lab"},
          {"chinese", "中文公司"},
          {"emoji (🎉)", "Party 🎉 Inc."}
        ] do
      test "parses metadata containing #{label} without crashing" do
        xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                             entityID="https://sp.example.com/saml">
          <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:AssertionConsumerService index="0" isDefault="true"
                                         Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                         Location="https://sp.example.com/saml/acs"/>
          </md:SPSSODescriptor>
          <md:Organization>
            <md:OrganizationName xml:lang="fr">#{unquote(sample)}</md:OrganizationName>
            <md:OrganizationDisplayName xml:lang="fr">#{unquote(sample)}</md:OrganizationDisplayName>
            <md:OrganizationURL xml:lang="fr">https://example.com</md:OrganizationURL>
          </md:Organization>
        </md:EntityDescriptor>
        """

        assert {:ok, %ValidationResult{}} = Metadata.validate(xml)
      end
    end
  end

  describe "root element" do
    test "flags <EntitiesDescriptor> as :entities_descriptor_not_supported" do
      xml = read_fixture("entities_descriptor.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :entities_descriptor_not_supported in codes(errors)
    end

    test "flags non-SAML root as :invalid_root_element" do
      xml = read_fixture("invalid_root.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :invalid_root_element in codes(errors)
    end
  end

  describe "entityID rules" do
    test "flags missing entityID" do
      xml = read_fixture("missing_entity_id.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :missing_entity_id in codes(errors)
    end

    test "flags entityID over 1024 bytes" do
      long_id = "https://sp.example.com/" <> String.duplicate("a", 1100)

      xml = """
      <?xml version="1.0"?>
      <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="#{long_id}">
        <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:AssertionConsumerService index="0" isDefault="true"
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://sp.example.com/saml/acs"/>
        </md:SPSSODescriptor>
      </md:EntityDescriptor>
      """

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :entity_id_too_long in codes(errors)
    end
  end

  describe "role descriptor rules" do
    test "flags metadata with neither SPSSO nor IDPSSO descriptor" do
      xml = read_fixture("missing_role_descriptor.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :missing_role_descriptor in codes(errors)
    end

    test "flags descriptor missing SAML 2.0 protocol support" do
      xml = read_fixture("missing_saml2_protocol.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :missing_saml2_protocol_support in codes(errors)
    end
  end

  describe "SP-specific rules" do
    test "flags SP metadata with no AssertionConsumerService" do
      xml = read_fixture("missing_acs.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :missing_acs in codes(errors)
    end

    test "flags ACS with HTTP-Redirect binding" do
      xml = read_fixture("acs_http_redirect.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :invalid_acs_binding in codes(errors)

      # Path should reference the offending ACS position
      err = Enum.find(errors, &(&1.code == :invalid_acs_binding))
      assert err.path =~ "AssertionConsumerService[2]"
    end

    test "flags SP metadata with no HTTP-POST ACS (Artifact+PAOS only)" do
      xml = read_fixture("acs_missing_http_post.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :missing_http_post_acs in codes(errors)
    end

    test ":ignore silences :missing_http_post_acs for ECP/Artifact-only SPs" do
      xml = read_fixture("acs_missing_http_post.xml")

      assert {:ok, %ValidationResult{errors: [], warnings: []}} =
               Metadata.validate(xml, ignore: [:missing_http_post_acs])
    end

    test "flags duplicate ACS index" do
      xml = read_fixture("acs_duplicate_index.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :duplicate_acs_index in codes(errors)
    end

    test "flags more than one ACS with isDefault=\"true\"" do
      xml = read_fixture("acs_multiple_default.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :multiple_default_acs in codes(errors)
    end
  end

  describe "IdP-specific rules" do
    test "flags IdP metadata with no SingleSignOnService" do
      xml = read_fixture("missing_sso.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :missing_sso_service in codes(errors)
    end

    test "flags invalid SingleLogoutService binding" do
      xml = read_fixture("slo_invalid_binding.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :invalid_slo_binding in codes(errors)
    end
  end

  describe ":ignore option" do
    test "removes listed codes from both errors and warnings" do
      xml = read_fixture("acs_http_redirect.xml")

      # Without ignore: :invalid_acs_binding is present
      assert {:error, %ValidationResult{errors: before_errors}} = Metadata.validate(xml)
      assert :invalid_acs_binding in codes(before_errors)

      # With ignore: it is dropped; since it was the only error, result is :ok
      assert {:ok, %ValidationResult{errors: [], warnings: []}} =
               Metadata.validate(xml, ignore: [:invalid_acs_binding])
    end

    test "accepts an empty :ignore list" do
      xml = read_fixture("sp_clean.xml")

      assert {:ok, %ValidationResult{errors: [], warnings: []}} =
               Metadata.validate(xml, ignore: [])
    end
  end

  describe "certificate rules" do
    test "flags <md:KeyDescriptor> without <ds:X509Certificate>" do
      xml = read_fixture("keydescriptor_missing_cert.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :missing_x509_certificate in codes(errors)
    end

    test "flags <ds:X509Certificate> with non-base64 content" do
      xml = read_fixture("keydescriptor_invalid_cert.xml")

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :invalid_x509_certificate in codes(errors)
    end

    test "flags base64 content that decodes but is not a valid X.509 cert" do
      garbage_b64 = Base.encode64("hello world this is not a der cert")
      xml = sp_metadata_with_keys([key_descriptor("signing", garbage_b64)])

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :invalid_x509_certificate in codes(errors)
    end

    test "accepts a spec-clean SP with a freshly-issued signing cert" do
      cert = CertFactory.signing()
      xml = sp_metadata_with_keys([key_descriptor("signing", cert.b64)])

      assert {:ok, %ValidationResult{errors: [], warnings: []}} = Metadata.validate(xml)
    end

    test "flags an expired signing cert with :certificate_expired" do
      cert = CertFactory.expired()
      xml = sp_metadata_with_keys([key_descriptor("signing", cert.b64)])

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)
      assert :certificate_expired in codes(errors)

      err = Enum.find(errors, &(&1.code == :certificate_expired))
      assert err.path =~ "SPSSODescriptor/KeyDescriptor"
      assert err.path =~ "X509Certificate"
    end

    test ":ignore silences :certificate_expired" do
      cert = CertFactory.expired()
      xml = sp_metadata_with_keys([key_descriptor("signing", cert.b64)])

      assert {:ok, %ValidationResult{errors: [], warnings: []}} =
               Metadata.validate(xml, ignore: [:certificate_expired])
    end

    test "indexes paths when multiple KeyDescriptors are present" do
      signing = CertFactory.signing()
      encryption = CertFactory.encryption()
      expired = CertFactory.expired()

      xml =
        sp_metadata_with_keys([
          key_descriptor("signing", signing.b64),
          key_descriptor("encryption", encryption.b64),
          key_descriptor("signing", expired.b64)
        ])

      assert {:error, %ValidationResult{errors: errors}} = Metadata.validate(xml)

      err = Enum.find(errors, &(&1.code == :certificate_expired))
      assert err
      assert err.path =~ "KeyDescriptor[3]"
    end

    test "does not fire on metadata with no <md:KeyDescriptor>" do
      assert {:ok, %ValidationResult{errors: [], warnings: []}} =
               Metadata.validate(read_fixture("sp_clean.xml"))

      assert {:ok, %ValidationResult{errors: [], warnings: []}} =
               Metadata.validate(read_fixture("idp_clean.xml"))
    end
  end
end
