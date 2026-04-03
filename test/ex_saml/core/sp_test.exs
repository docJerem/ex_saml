defmodule ExSaml.Core.SpTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.{Contact, Org, Sp, SpConfig, Subject}

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlNamespace,
    Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl")
  )

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp base_sp do
    %SpConfig{
      metadata_uri: "https://sp.example.com/metadata",
      consume_uri: "https://sp.example.com/consume",
      org: %Org{name: "Test Org", displayname: "Test Org Display", url: "https://example.com"},
      tech: %Contact{name: "Admin", email: "admin@example.com"}
    }
  end

  defp find_attr(xml_elem, name) do
    xmlElement(xml_elem, :attributes)
    |> Enum.find(fn attr ->
      Record.is_record(attr, :xmlAttribute) and xmlAttribute(attr, :name) == name
    end)
    |> case do
      nil -> nil
      attr -> xmlAttribute(attr, :value)
    end
  end

  defp find_child(xml_elem, child_name) do
    xmlElement(xml_elem, :content)
    |> Enum.find(fn
      rec when Record.is_record(rec, :xmlElement) ->
        xmlElement(rec, :name) == child_name

      _ ->
        false
    end)
  end

  # Normalise attribute value to a binary for comparison, since xmerl
  # attributes may be stored as charlists or binaries depending on
  # how the XML element was constructed.
  defp attr_to_string(nil), do: nil
  defp attr_to_string(val) when is_list(val), do: to_string(val)
  defp attr_to_string(val) when is_binary(val), do: val

  # ---------------------------------------------------------------------------
  # setup/1
  # ---------------------------------------------------------------------------

  describe "setup/1" do
    test "validates and returns SP config with metadata_uri and consume_uri" do
      sp = base_sp()
      result = Sp.setup(sp)
      assert %SpConfig{} = result
      assert result.metadata_uri == "https://sp.example.com/metadata"
      assert result.consume_uri == "https://sp.example.com/consume"
    end

    test "raises when metadata_uri is empty" do
      sp = %{base_sp() | metadata_uri: ""}

      assert_raise RuntimeError, ~r/must specify metadata URI/, fn ->
        Sp.setup(sp)
      end
    end

    test "raises when consume_uri is empty" do
      sp = %{base_sp() | consume_uri: ""}

      assert_raise RuntimeError, ~r/must specify consume URI/, fn ->
        Sp.setup(sp)
      end
    end

    test "raises when sp_sign_requests is true but key is nil" do
      sp = %{base_sp() | sp_sign_requests: true, key: nil}

      assert_raise RuntimeError, ~r/must specify a key to sign requests/, fn ->
        Sp.setup(sp)
      end
    end

    test "enables signing when both key and certificate are present" do
      sp = %{base_sp() | key: :fake_key, certificate: "fake_cert"}
      result = Sp.setup(sp)
      assert result.sp_sign_requests == true
      assert result.sp_sign_metadata == true
    end

    test "does not enable signing when key is nil" do
      sp = base_sp()
      result = Sp.setup(sp)
      assert result.sp_sign_requests == false
      assert result.sp_sign_metadata == false
    end
  end

  # ---------------------------------------------------------------------------
  # generate_authn_request/3
  # ---------------------------------------------------------------------------

  describe "generate_authn_request/3" do
    test "produces XML element with required attributes (unsigned path)" do
      sp = base_sp()
      xml = Sp.generate_authn_request("https://idp.example.com/sso", sp, nil)

      assert Record.is_record(xml, :xmlElement)
      assert xmlElement(xml, :name) == :"samlp:AuthnRequest"

      assert attr_to_string(find_attr(xml, :Destination)) == "https://idp.example.com/sso"
      assert attr_to_string(find_attr(xml, :Version)) == "2.0"
      assert find_attr(xml, :ProtocolBinding) != nil

      # Should have an ID attribute added
      assert find_attr(xml, :ID) != nil

      # IssueInstant should be set
      issue_instant = find_attr(xml, :IssueInstant)
      assert issue_instant != nil
    end

    test "produces XML with Issuer child element" do
      sp = base_sp()
      xml = Sp.generate_authn_request("https://idp.example.com/sso", sp, nil)

      issuer_elem = find_child(xml, :"saml:Issuer")
      assert issuer_elem != nil
    end

    test "uses entity_id as issuer when set" do
      sp = %{base_sp() | entity_id: "custom-entity-id"}
      xml = Sp.generate_authn_request("https://idp.example.com/sso", sp, nil)

      issuer_elem = find_child(xml, :"saml:Issuer")
      assert issuer_elem != nil

      [text | _] = xmlElement(issuer_elem, :content)
      assert to_string(xmlText(text, :value)) == "custom-entity-id"
    end

    test "falls back to metadata_uri as issuer when entity_id is nil" do
      sp = base_sp()
      xml = Sp.generate_authn_request("https://idp.example.com/sso", sp, nil)

      issuer_elem = find_child(xml, :"saml:Issuer")
      assert issuer_elem != nil

      [text | _] = xmlElement(issuer_elem, :content)
      assert to_string(xmlText(text, :value)) == "https://sp.example.com/metadata"
    end

    test "arity-2 version delegates to arity-3 with nil format" do
      sp = base_sp()
      xml = Sp.generate_authn_request("https://idp.example.com/sso", sp)

      assert Record.is_record(xml, :xmlElement)
      assert xmlElement(xml, :name) == :"samlp:AuthnRequest"
    end
  end

  # ---------------------------------------------------------------------------
  # generate_metadata/1
  # ---------------------------------------------------------------------------

  describe "generate_metadata/1" do
    test "produces EntityDescriptor XML with SPSSODescriptor" do
      sp = base_sp()
      xml = Sp.generate_metadata(sp)

      assert Record.is_record(xml, :xmlElement)
      assert xmlElement(xml, :name) == :"md:EntityDescriptor"

      # Should have entityID attribute
      entity_id = find_attr(xml, :entityID)
      assert entity_id != nil

      # Should contain SPSSODescriptor child
      sp_sso = find_child(xml, :"md:SPSSODescriptor")
      assert sp_sso != nil
    end

    test "metadata contains entity_id matching metadata_uri" do
      sp = base_sp()
      xml = Sp.generate_metadata(sp)

      entity_id = find_attr(xml, :entityID)
      assert attr_to_string(entity_id) == "https://sp.example.com/metadata"
    end

    test "metadata uses custom entity_id when set" do
      sp = %{base_sp() | entity_id: "custom-entity"}
      xml = Sp.generate_metadata(sp)

      entity_id = find_attr(xml, :entityID)
      assert attr_to_string(entity_id) == "custom-entity"
    end

    test "metadata contains Organization element" do
      sp = base_sp()
      xml = Sp.generate_metadata(sp)

      org_elem = find_child(xml, :"md:Organization")
      assert org_elem != nil
    end

    test "metadata contains ContactPerson element" do
      sp = base_sp()
      xml = Sp.generate_metadata(sp)

      contact_elem = find_child(xml, :"md:ContactPerson")
      assert contact_elem != nil
    end

    test "SPSSODescriptor has protocol support enumeration" do
      sp = base_sp()
      xml = Sp.generate_metadata(sp)

      sp_sso = find_child(xml, :"md:SPSSODescriptor")
      assert sp_sso != nil

      proto = find_attr(sp_sso, :protocolSupportEnumeration)
      assert attr_to_string(proto) == "urn:oasis:names:tc:SAML:2.0:protocol"
    end

    test "metadata has an ID attribute (unsigned path)" do
      sp = base_sp()
      xml = Sp.generate_metadata(sp)

      assert find_attr(xml, :ID) != nil
    end
  end

  # ---------------------------------------------------------------------------
  # generate_logout_request/4
  # ---------------------------------------------------------------------------

  describe "generate_logout_request/4" do
    test "produces LogoutRequest XML element with required attributes" do
      sp = base_sp()
      subject = %Subject{name: "user@example.com"}

      xml = Sp.generate_logout_request("https://idp.example.com/slo", "", subject, sp)

      assert Record.is_record(xml, :xmlElement)
      assert xmlElement(xml, :name) == :"samlp:LogoutRequest"

      assert attr_to_string(find_attr(xml, :Destination)) == "https://idp.example.com/slo"
      assert attr_to_string(find_attr(xml, :Version)) == "2.0"
      assert find_attr(xml, :ID) != nil
    end

    test "contains Issuer and NameID child elements" do
      sp = base_sp()
      subject = %Subject{name: "user@example.com"}

      xml = Sp.generate_logout_request("https://idp.example.com/slo", "", subject, sp)

      issuer = find_child(xml, :"saml:Issuer")
      assert issuer != nil

      name_id = find_child(xml, :"saml:NameID")
      assert name_id != nil
    end

    test "arity-3 convenience builds Subject from name_id string" do
      sp = base_sp()

      xml = Sp.generate_logout_request("https://idp.example.com/slo", "user@example.com", sp)

      assert Record.is_record(xml, :xmlElement)
      assert xmlElement(xml, :name) == :"samlp:LogoutRequest"
    end
  end

  # ---------------------------------------------------------------------------
  # generate_logout_response/3
  # ---------------------------------------------------------------------------

  describe "generate_logout_response/3" do
    test "produces LogoutResponse XML element with required attributes" do
      sp = base_sp()

      xml = Sp.generate_logout_response("https://idp.example.com/slo", :success, sp)

      assert Record.is_record(xml, :xmlElement)
      assert xmlElement(xml, :name) == :"samlp:LogoutResponse"

      assert attr_to_string(find_attr(xml, :Destination)) == "https://idp.example.com/slo"
      assert attr_to_string(find_attr(xml, :Version)) == "2.0"
      assert find_attr(xml, :ID) != nil
    end

    test "contains Issuer and Status child elements" do
      sp = base_sp()

      xml = Sp.generate_logout_response("https://idp.example.com/slo", :success, sp)

      issuer = find_child(xml, :"saml:Issuer")
      assert issuer != nil

      status = find_child(xml, :"samlp:Status")
      assert status != nil
    end
  end
end
