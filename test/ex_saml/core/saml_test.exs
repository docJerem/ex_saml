defmodule ExSaml.Core.SamlTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.{Assertion, Response, Saml, Subject, Util}

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

  defp parse_xml(str) do
    {doc, _} = :xmerl_scan.string(String.to_charlist(str), [{:namespace_conformant, true}])
    doc
  end

  # ---------------------------------------------------------------------------
  # decode_response/1
  #
  # NOTE: The decode_response tests below exercise the public API by parsing
  # raw XML strings. They require xmerl_xpath namespace prefixes to be
  # charlists. If the namespace definitions in Saml use binary strings
  # instead (known issue), these tests will fail until that is corrected.
  # ---------------------------------------------------------------------------

  describe "decode_response/1" do
    @tag :decode
    test "parses a basic SAML Response with Version, IssueInstant, and Destination" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="2013-01-01T01:01:01Z" ) <>
          ~s(Destination="foo"></samlp:Response>)

      doc = parse_xml(xml)
      assert {:ok, %Response{} = resp} = Saml.decode_response(doc)
      assert resp.issue_instant == "2013-01-01T01:01:01Z"
      assert resp.destination == "foo"
      assert resp.status == :unknown
    end

    @tag :decode
    test "returns error when Version attribute is missing" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(IssueInstant="2013-01-01T01:01:01Z" Destination="foo"></samlp:Response>)

      doc = parse_xml(xml)
      assert {:error, :bad_version} = Saml.decode_response(doc)
    end

    @tag :decode
    test "returns error when IssueInstant attribute is missing" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" Destination="foo"></samlp:Response>)

      doc = parse_xml(xml)
      assert {:error, :bad_response} = Saml.decode_response(doc)
    end

    @tag :decode
    test "Destination is optional" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="2013-01-01T01:01:01Z"></samlp:Response>)

      doc = parse_xml(xml)
      assert {:ok, %Response{} = resp} = Saml.decode_response(doc)
      assert resp.issue_instant == "2013-01-01T01:01:01Z"
      assert resp.status == :unknown
    end

    @tag :decode
    test "parses status code and issuer" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="2013-01-01T01:01:01Z">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>) <>
          ~s(</samlp:Response>)

      doc = parse_xml(xml)
      assert {:ok, %Response{} = resp} = Saml.decode_response(doc)
      assert resp.issue_instant == "2013-01-01T01:01:01Z"
      assert resp.status == :success
      assert resp.issuer == "foo"
    end
  end

  # ---------------------------------------------------------------------------
  # decode_assertion/1 (via decode_response with embedded assertion)
  # ---------------------------------------------------------------------------

  describe "decode_assertion/1" do
    @tag :decode
    test "parses full assertion with subject and recipient" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="2013-01-01T01:01:01Z">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>) <>
          ~s(<saml:Assertion Version="2.0" IssueInstant="test">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<saml:Subject>) <>
          ~s(<saml:NameID>foobar</saml:NameID>) <>
          ~s(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">) <>
          ~s(<saml:SubjectConfirmationData Recipient="foobar123" />) <>
          ~s(</saml:SubjectConfirmation>) <>
          ~s(</saml:Subject>) <>
          ~s(</saml:Assertion>) <>
          ~s(</samlp:Response>)

      doc = parse_xml(xml)
      assert {:ok, %Response{} = resp} = Saml.decode_response(doc)
      assert resp.issue_instant == "2013-01-01T01:01:01Z"
      assert resp.issuer == "foo"
      assert resp.status == :success

      assert %Assertion{} = resp.assertion
      assert resp.assertion.issue_instant == "test"
      assert resp.assertion.issuer == "foo"
      assert resp.assertion.recipient == "foobar123"

      assert %Subject{} = resp.assertion.subject
      assert resp.assertion.subject.name == "foobar"
      assert resp.assertion.subject.confirmation_method == :bearer
    end

    @tag :decode
    test "returns error when assertion has no Recipient" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="2013-01-01T01:01:01Z">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>) <>
          ~s(<saml:Assertion Version="2.0" IssueInstant="test">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<saml:Subject>) <>
          ~s(<saml:NameID>foobar</saml:NameID>) <>
          ~s(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" />) <>
          ~s(</saml:Subject>) <>
          ~s(</saml:Assertion>) <>
          ~s(</samlp:Response>)

      doc = parse_xml(xml)
      assert {:error, :bad_recipient} = Saml.decode_response(doc)
    end

    @tag :decode
    test "returns error when embedded assertion has no Version" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="2013-01-01T01:01:01Z">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>) <>
          ~s(<saml:Assertion></saml:Assertion>) <>
          ~s(</samlp:Response>)

      doc = parse_xml(xml)
      assert {:error, :bad_version} = Saml.decode_response(doc)
    end
  end

  # ---------------------------------------------------------------------------
  # decode_assertion_conditions (via decode_response)
  # ---------------------------------------------------------------------------

  describe "decode_conditions" do
    @tag :decode
    test "parses NotBefore, NotOnOrAfter, and Audience from Conditions element" do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
          ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="2013-01-01T01:01:01Z">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>) <>
          ~s(<saml:Assertion Version="2.0" IssueInstant="test">) <>
          ~s(<saml:Issuer>foo</saml:Issuer>) <>
          ~s(<saml:Subject>) <>
          ~s(<saml:NameID>foobar</saml:NameID>) <>
          ~s(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">) <>
          ~s(<saml:SubjectConfirmationData Recipient="foobar123" />) <>
          ~s(</saml:SubjectConfirmation>) <>
          ~s(</saml:Subject>) <>
          ~s(<saml:Conditions NotBefore="before" NotOnOrAfter="notafter">) <>
          ~s(<saml:AudienceRestriction>) <>
          ~s(<saml:Audience>foobaraudience</saml:Audience>) <>
          ~s(</saml:AudienceRestriction>) <>
          ~s(</saml:Conditions>) <>
          ~s(</saml:Assertion>) <>
          ~s(</samlp:Response>)

      doc = parse_xml(xml)

      assert {:ok, %Response{assertion: %Assertion{conditions: conds}}} =
               Saml.decode_response(doc)

      sorted = Enum.sort(conds)
      assert {:audience, "foobaraudience"} in sorted
      assert {:not_before, "before"} in sorted
      assert {:not_on_or_after, "notafter"} in sorted
    end
  end

  # ---------------------------------------------------------------------------
  # decode_assertion_attributes
  # ---------------------------------------------------------------------------

  describe "decode_attributes" do
    @tag :decode
    test "parses AttributeStatement with single-value and multi-value attributes" do
      xml =
        ~s(<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="test">) <>
          ~s(<saml:Subject>) <>
          ~s(<saml:NameID>foobar</saml:NameID>) <>
          ~s(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">) <>
          ~s(<saml:SubjectConfirmationData Recipient="foobar123" />) <>
          ~s(</saml:SubjectConfirmation>) <>
          ~s(</saml:Subject>) <>
          ~s(<saml:AttributeStatement>) <>
          ~s(<saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3">) <>
          ~s(<saml:AttributeValue>test@test.com</saml:AttributeValue>) <>
          ~s(</saml:Attribute>) <>
          ~s(<saml:Attribute Name="foo">) <>
          ~s(<saml:AttributeValue>george</saml:AttributeValue>) <>
          ~s(<saml:AttributeValue>bar</saml:AttributeValue>) <>
          ~s(</saml:Attribute>) <>
          ~s(<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">) <>
          ~s(<saml:AttributeValue>test@test.com</saml:AttributeValue>) <>
          ~s(</saml:Attribute>) <>
          ~s(</saml:AttributeStatement>) <>
          ~s(</saml:Assertion>)

      doc = parse_xml(xml)
      assert {:ok, %Assertion{attributes: attrs}} = Saml.decode_assertion(doc)

      sorted = Enum.sort(attrs)

      assert {"emailaddress", "test@test.com"} in sorted
      assert {:mail, "test@test.com"} in sorted

      # The multi-value attribute "foo" should have a list of values
      foo_entry = Enum.find(sorted, fn {k, _v} -> k == "foo" end)
      assert foo_entry != nil
      {_, foo_vals} = foo_entry
      assert is_list(foo_vals)
      assert "george" in foo_vals
      assert "bar" in foo_vals
    end
  end

  # ---------------------------------------------------------------------------
  # validate_assertion/3
  #
  # These tests build XML elements programmatically via build_nsinfo,
  # matching the approach used in the original Erlang EUnit tests.
  #
  # Tagged :validate because they depend on xmerl_xpath namespace resolution
  # for elements built with build_nsinfo, which has a compatibility issue
  # with the current OTP/xmerl version. Run with --include validate to test.
  # ---------------------------------------------------------------------------

  describe "validate_assertion/3" do
    @tag :validate
    test "good assertion with matching recipient and audience passes validation" do
      now = :erlang.localtime() |> :erlang.localtime_to_universaltime()
      death_secs = :calendar.datetime_to_gregorian_seconds(now) + 60
      death = Util.datetime_to_saml(:calendar.gregorian_seconds_to_datetime(death_secs))

      ns =
        xmlNamespace(nodes: [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}])

      elem =
        Util.build_nsinfo(
          ns,
          xmlElement(
            name: :"saml:Assertion",
            attributes: [
              xmlAttribute(
                name: :"xmlns:saml",
                value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"
              ),
              xmlAttribute(name: :Version, value: ~c"2.0"),
              xmlAttribute(name: :IssueInstant, value: ~c"now")
            ],
            content: [
              xmlElement(
                name: :"saml:Subject",
                content: [
                  xmlElement(
                    name: :"saml:SubjectConfirmation",
                    content: [
                      xmlElement(
                        name: :"saml:SubjectConfirmationData",
                        attributes: [
                          xmlAttribute(name: :Recipient, value: ~c"foobar"),
                          xmlAttribute(name: :NotOnOrAfter, value: String.to_charlist(death))
                        ]
                      )
                    ]
                  )
                ]
              ),
              xmlElement(
                name: :"saml:Conditions",
                content: [
                  xmlElement(
                    name: :"saml:AudienceRestriction",
                    content: [
                      xmlElement(
                        name: :"saml:Audience",
                        content: [xmlText(value: ~c"foo")]
                      )
                    ]
                  )
                ]
              )
            ]
          )
        )

      assert {:ok, %Assertion{} = assertion} =
               Saml.validate_assertion(elem, "foobar", "foo")

      assert assertion.issue_instant == "now"
      assert assertion.recipient == "foobar"
      assert {:audience, "foo"} in assertion.conditions
    end

    @tag :validate
    test "bad recipient returns error" do
      now = :erlang.localtime() |> :erlang.localtime_to_universaltime()
      death_secs = :calendar.datetime_to_gregorian_seconds(now) + 60
      death = Util.datetime_to_saml(:calendar.gregorian_seconds_to_datetime(death_secs))

      ns =
        xmlNamespace(nodes: [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}])

      elem =
        Util.build_nsinfo(
          ns,
          xmlElement(
            name: :"saml:Assertion",
            attributes: [
              xmlAttribute(
                name: :"xmlns:saml",
                value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"
              ),
              xmlAttribute(name: :Version, value: ~c"2.0"),
              xmlAttribute(name: :IssueInstant, value: ~c"now")
            ],
            content: [
              xmlElement(
                name: :"saml:Subject",
                content: [
                  xmlElement(
                    name: :"saml:SubjectConfirmation",
                    content: [
                      xmlElement(
                        name: :"saml:SubjectConfirmationData",
                        attributes: [
                          xmlAttribute(name: :Recipient, value: ~c"foobar"),
                          xmlAttribute(name: :NotOnOrAfter, value: String.to_charlist(death))
                        ]
                      )
                    ]
                  )
                ]
              ),
              xmlElement(
                name: :"saml:Conditions",
                content: [
                  xmlElement(
                    name: :"saml:AudienceRestriction",
                    content: [
                      xmlElement(
                        name: :"saml:Audience",
                        content: [xmlText(value: ~c"foo")]
                      )
                    ]
                  )
                ]
              )
            ]
          )
        )

      assert {:error, :bad_recipient} =
               Saml.validate_assertion(elem, "wrong", "something")
    end

    @tag :validate
    test "bad audience returns error" do
      now = :erlang.localtime() |> :erlang.localtime_to_universaltime()
      death_secs = :calendar.datetime_to_gregorian_seconds(now) + 60
      death = Util.datetime_to_saml(:calendar.gregorian_seconds_to_datetime(death_secs))

      ns =
        xmlNamespace(nodes: [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}])

      elem =
        Util.build_nsinfo(
          ns,
          xmlElement(
            name: :"saml:Assertion",
            attributes: [
              xmlAttribute(
                name: :"xmlns:saml",
                value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"
              ),
              xmlAttribute(name: :Version, value: ~c"2.0"),
              xmlAttribute(name: :IssueInstant, value: ~c"now")
            ],
            content: [
              xmlElement(
                name: :"saml:Subject",
                content: [
                  xmlElement(
                    name: :"saml:SubjectConfirmation",
                    content: [
                      xmlElement(
                        name: :"saml:SubjectConfirmationData",
                        attributes: [
                          xmlAttribute(name: :Recipient, value: ~c"foobar"),
                          xmlAttribute(name: :NotOnOrAfter, value: String.to_charlist(death))
                        ]
                      )
                    ]
                  )
                ]
              ),
              xmlElement(
                name: :"saml:Conditions",
                content: [
                  xmlElement(
                    name: :"saml:AudienceRestriction",
                    content: [
                      xmlElement(
                        name: :"saml:Audience",
                        content: [xmlText(value: ~c"foo")]
                      )
                    ]
                  )
                ]
              )
            ]
          )
        )

      assert {:error, :bad_audience} =
               Saml.validate_assertion(elem, "foobar", "wrong_audience")
    end

    @tag :validate
    test "missing SubjectConfirmationData returns bad_recipient error" do
      ns =
        xmlNamespace(nodes: [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}])

      elem =
        Util.build_nsinfo(
          ns,
          xmlElement(
            name: :"saml:Assertion",
            attributes: [
              xmlAttribute(
                name: :"xmlns:saml",
                value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"
              ),
              xmlAttribute(name: :Version, value: ~c"2.0"),
              xmlAttribute(name: :IssueInstant, value: ~c"now")
            ],
            content: [
              xmlElement(
                name: :"saml:Subject",
                content: [
                  xmlElement(
                    name: :"saml:SubjectConfirmation",
                    content: []
                  )
                ]
              ),
              xmlElement(
                name: :"saml:Conditions",
                content: [
                  xmlElement(
                    name: :"saml:AudienceRestriction",
                    content: [
                      xmlElement(
                        name: :"saml:Audience",
                        content: [xmlText(value: ~c"foo")]
                      )
                    ]
                  )
                ]
              )
            ]
          )
        )

      assert {:error, :bad_recipient} =
               Saml.validate_assertion(elem, "", "")
    end
  end

  # ---------------------------------------------------------------------------
  # validate_stale_assertion
  # ---------------------------------------------------------------------------

  describe "validate_stale_assertion" do
    @tag :validate
    test "old assertion returns stale_assertion error" do
      old_stamp = Util.datetime_to_saml({{1990, 1, 1}, {1, 1, 1}})

      ns =
        xmlNamespace(nodes: [{~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"}])

      elem =
        Util.build_nsinfo(
          ns,
          xmlElement(
            name: :"saml:Assertion",
            attributes: [
              xmlAttribute(
                name: :"xmlns:saml",
                value: ~c"urn:oasis:names:tc:SAML:2.0:assertion"
              ),
              xmlAttribute(name: :Version, value: ~c"2.0"),
              xmlAttribute(name: :IssueInstant, value: ~c"now")
            ],
            content: [
              xmlElement(
                name: :"saml:Subject",
                content: [
                  xmlElement(
                    name: :"saml:SubjectConfirmation",
                    content: [
                      xmlElement(
                        name: :"saml:SubjectConfirmationData",
                        attributes: [
                          xmlAttribute(name: :Recipient, value: ~c"foobar"),
                          xmlAttribute(
                            name: :NotOnOrAfter,
                            value: String.to_charlist(old_stamp)
                          )
                        ]
                      )
                    ]
                  )
                ]
              )
            ]
          )
        )

      assert {:error, :stale_assertion} =
               Saml.validate_assertion(elem, "foobar", "foo")
    end
  end
end
