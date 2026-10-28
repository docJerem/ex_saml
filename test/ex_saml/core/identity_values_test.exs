defmodule ExSaml.Core.IdentityValuesTest do
  @moduledoc """
  NameID and AttributeValue are read whole, as the concatenation of their text
  nodes; a comment or a processing instruction inside one rejects the
  assertion. The signature digest is computed
  without comments, so the check runs on the parsed tree, after verification.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias ExSaml.Core.{Saml, Sp, SpConfig, Util}
  alias ExSaml.Core.Xml.{Dsig, SafeXml}

  @recipient "https://sp.example.com/consume"
  @audience "https://sp.example.com/sp"

  defp in_secs(offset) do
    :erlang.localtime()
    |> :erlang.localtime_to_universaltime()
    |> :calendar.datetime_to_gregorian_seconds()
    |> Kernel.+(offset)
    |> :calendar.gregorian_seconds_to_datetime()
    |> Util.datetime_to_saml()
  end

  # `name_id` and `email` are inserted verbatim, so they may carry markup.
  defp assertion_string(name_id, email) do
    name_id_el = if name_id, do: "<saml:NameID>#{name_id}</saml:NameID>", else: ""

    """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="#{in_secs(-10)}"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject>#{name_id_el}<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="#{@recipient}" NotOnOrAfter="#{in_secs(300)}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="#{in_secs(300)}"><saml:AudienceRestriction><saml:Audience>#{@audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>#{email}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>a</saml:AttributeValue><saml:AttributeValue>b</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>
    """
  end

  defp parse(xml) do
    {:ok, doc} = SafeXml.scan(xml)
    doc
  end

  defp validate(name_id, email),
    do:
      name_id
      |> assertion_string(email)
      |> parse()
      |> Saml.validate_assertion(@recipient, @audience)

  describe "values read whole" do
    test "plain values are read as before" do
      assert {:ok, assertion} = validate("user@example.com", "user@example.com")
      assert assertion.subject.name == "user@example.com"
      assert {"email", "user@example.com"} in assertion.attributes
      assert {"groups", ["a", "b"]} in assertion.attributes
    end

    test "a NameID split across text and CDATA is read whole" do
      assert {:ok, assertion} = validate("user@<![CDATA[example]]>.com", "user@example.com")
      assert assertion.subject.name == "user@example.com"
    end

    test "an AttributeValue split across text and CDATA is read whole" do
      assert {:ok, assertion} = validate("user@example.com", "user@<![CDATA[example]]>.com")
      assert {"email", "user@example.com"} in assertion.attributes
    end
  end

  describe "comments and processing instructions" do
    test "a comment in the NameID rejects the assertion" do
      assert {:error, :bad_assertion} =
               validate("user@example.com<!---->.other.test", "user@example.com")
    end

    test "a processing instruction in the NameID rejects the assertion" do
      assert {:error, :bad_assertion} =
               validate("user@example.com<?x y?>.other.test", "user@example.com")
    end

    test "a comment in an AttributeValue rejects the assertion" do
      assert {:error, :bad_assertion} =
               validate("user@example.com", "user@example.com<!---->.other.test")
    end

    test "decode_assertion/1 rejects it too" do
      xml = "user@example.com<!---->.other.test" |> assertion_string("x") |> parse()
      assert {:error, :bad_assertion} = Saml.decode_assertion(xml)
    end
  end

  # The NameID is optional (Core §2.4.1): the Core accepts an assertion without
  # one. SPHandler rejects a sign-in whose user key is empty.
  describe "empty NameID" do
    test "an empty NameID reads as an empty name" do
      assert {:ok, %{subject: %{name: ""}}} = validate("", "user@example.com")
    end

    test "a missing NameID reads as an empty name" do
      assert {:ok, %{subject: %{name: ""}}} = validate(nil, "user@example.com")
    end

    test "an EncryptedID, not supported, reads as an empty name and is logged" do
      log =
        capture_log(fn ->
          assert {:ok, %{subject: %{name: ""}}} =
                   "<saml:EncryptedID><EncryptedData/></saml:EncryptedID>"
                   |> assertion_string("user@example.com")
                   |> String.replace("<saml:NameID>", "")
                   |> String.replace("</saml:NameID>", "")
                   |> parse()
                   |> Saml.validate_assertion(@recipient, @audience)
        end)

      assert log =~ "Subject/EncryptedID is not supported"
    end
  end

  # The digest excludes comments: a comment added to a signed value keeps the
  # signature valid, so the rejection has to come from the parsed values.
  describe "signed assertions" do
    setup do
      sp_data =
        ExSaml.SpData.load_provider(%ExSaml.SpData{
          id: "sp1",
          certfile: "test/data/test.crt",
          keyfile: "test/data/test.pem"
        })

      sp = %SpConfig{
        consume_uri: @recipient,
        entity_id: @audience,
        idp_signs_assertions: true,
        idp_signs_envelopes: false,
        trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, sp_data.cert)}]
      }

      signed =
        "user@example.com.other.test"
        |> assertion_string("user@example.com.other.test")
        |> parse()
        |> Dsig.sign(sp_data.key, sp_data.cert, :rsa_sha256)
        |> List.wrap()
        |> :xmerl.export_simple(:xmerl_xml)
        |> :unicode.characters_to_binary()
        |> String.replace(~r/^<\?xml[^>]*\?>/, "")

      {:ok, sp: sp, signed: signed}
    end

    defp response(assertion) do
      parse("""
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="#{in_secs(-10)}"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>#{assertion}</samlp:Response>
      """)
    end

    test "the unaltered signed assertion is accepted", %{sp: sp, signed: signed} do
      assert {:ok, assertion} = Sp.validate_assertion(response(signed), sp)
      assert assertion.subject.name == "user@example.com.other.test"
    end

    test "a comment added to the signed NameID keeps the signature valid but is rejected",
         %{sp: sp, signed: signed} do
      altered =
        String.replace(
          signed,
          "<saml:NameID>user@example.com.other.test",
          "<saml:NameID>user@example.com<!---->.other.test"
        )

      refute altered == signed
      assert :ok = altered |> parse() |> Dsig.verify(sp.trusted_fingerprints)
      assert {:error, :bad_assertion} = Sp.validate_assertion(response(altered), sp)
    end

    test "a comment added to a signed AttributeValue is rejected", %{sp: sp, signed: signed} do
      altered =
        String.replace(
          signed,
          "<saml:AttributeValue>user@example.com.other.test",
          "<saml:AttributeValue>user@example.com<!---->.other.test"
        )

      refute altered == signed
      assert {:error, :bad_assertion} = Sp.validate_assertion(response(altered), sp)
    end
  end
end
