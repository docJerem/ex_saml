defmodule ExSaml.Core.SpXmlIdTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.{Contact, Org, Sp, SpConfig}

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  defp base_sp do
    %SpConfig{
      metadata_uri: "https://sp.example.com/metadata",
      consume_uri: "https://sp.example.com/consume",
      org: %Org{name: "Test Org", displayname: "Test Org Display", url: "https://example.com"},
      tech: %Contact{name: "Admin", email: "admin@example.com"}
    }
  end

  defp id_attr(xml) do
    xmlElement(xml, :attributes)
    |> Enum.find(fn attr ->
      Record.is_record(attr, :xmlAttribute) and xmlAttribute(attr, :name) == :ID
    end)
    |> case do
      nil -> nil
      attr -> attr |> xmlAttribute(:value) |> to_string()
    end
  end

  # The InResponseTo check is only as good as our ability to read back the id
  # we minted. If `xml_id/1` returned nil the check would silently never fire,
  # so both generation paths are pinned here.
  describe "xml_id/1" do
    test "reads back the ID on the unsigned path" do
      xml = Sp.generate_authn_request("https://idp.example.com/sso", base_sp(), nil)

      id = Sp.xml_id(xml)
      assert is_binary(id) and id != ""
      assert id_attr(xml) == id
    end

    test "reads back the ID on the signed path" do
      sp_data =
        ExSaml.SpData.load_provider(%ExSaml.SpData{
          id: "sp1",
          certfile: "test/data/test.crt",
          keyfile: "test/data/test.pem"
        })

      sp = %{base_sp() | sp_sign_requests: true, key: sp_data.key, certificate: sp_data.cert}
      xml = Sp.generate_authn_request("https://idp.example.com/sso", sp, nil)

      id = Sp.xml_id(xml)
      assert is_binary(id) and id != ""
      assert id_attr(xml) == id
    end

    test "returns nil for an element with no ID" do
      xml = xmlElement(name: :"samlp:AuthnRequest", attributes: [])
      assert Sp.xml_id(xml) == nil
    end
  end

  test "SpConfig.entity_id/1 falls back to the metadata URI" do
    assert SpConfig.entity_id(base_sp()) == "https://sp.example.com/metadata"
    assert SpConfig.entity_id(%{base_sp() | entity_id: "urn:sp"}) == "urn:sp"
  end
end
