defmodule ExSaml.AssertionTest do
  use ExUnit.Case, async: true

  alias ExSaml.Assertion
  alias ExSaml.Core

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp core_assertion(attributes) do
    %Core.Assertion{
      version: "2.0",
      issue_instant: "2026-09-29T10:00:00Z",
      recipient: "https://sp.example.com/acs",
      issuer: "https://idp.example.com",
      subject: %Core.Subject{name: "jane@example.com"},
      attributes: attributes
    }
  end

  defp parse_xml(str) do
    {doc, _} = :xmerl_scan.string(String.to_charlist(str), [{:namespace_conformant, true}])
    doc
  end

  # ---------------------------------------------------------------------------
  # from_core/1
  # ---------------------------------------------------------------------------

  describe "from_core/1" do
    test "keeps a multi-valued attribute decoded to binaries as a list" do
      core = core_assertion([{"group", ["Admins", "Developers", "Finance"]}])

      assert %Assertion{attributes: %{"group" => ["Admins", "Developers", "Finance"]}} =
               Assertion.from_core(core)
    end

    test "does not concatenate the values of a multi-valued attribute" do
      core = core_assertion([{"group", ["Admins", "Developers"]}])

      %Assertion{attributes: %{"group" => group}} = Assertion.from_core(core)

      refute group == "AdminsDevelopers"
    end

    test "keeps a single-valued binary attribute as a string" do
      core = core_assertion([{"email", "jane@example.com"}])

      assert %Assertion{attributes: %{"email" => "jane@example.com"}} = Assertion.from_core(core)
    end

    test "turns an empty attribute value into an empty string" do
      core = core_assertion([{"group", []}])

      assert %Assertion{attributes: %{"group" => ""}} = Assertion.from_core(core)
    end

    test "stringifies atom attribute names" do
      core = core_assertion([{:mail, "jane@example.com"}])

      assert %Assertion{attributes: %{"mail" => "jane@example.com"}} = Assertion.from_core(core)
    end

    test "joins a charlist attribute value into a single string" do
      core = core_assertion([{"email", ~c"jane@example.com"}])

      assert %Assertion{attributes: %{"email" => "jane@example.com"}} = Assertion.from_core(core)
    end

    test "maps a list of charlists to a list of strings" do
      core = core_assertion([{"group", [~c"Admins", ~c"Developers"]}])

      assert %Assertion{attributes: %{"group" => ["Admins", "Developers"]}} =
               Assertion.from_core(core)
    end

    test "stringifies conditions and authn alongside attributes" do
      core = %{
        core_assertion([{"email", "jane@example.com"}])
        | conditions: [
            audience: "https://sp.example.com",
            not_on_or_after: ~c"2026-09-29T11:00:00Z"
          ],
          authn: [authn_instant: ~c"2026-09-29T10:00:00Z"]
      }

      assert %Assertion{
               conditions: %{
                 "audience" => "https://sp.example.com",
                 "not_on_or_after" => "2026-09-29T11:00:00Z"
               },
               authn: %{"authn_instant" => "2026-09-29T10:00:00Z"}
             } = Assertion.from_core(core)
    end

    test "copies the scalar assertion fields" do
      assertion = Assertion.from_core(core_assertion([]))

      assert assertion.version == "2.0"
      assert assertion.issue_instant == "2026-09-29T10:00:00Z"
      assert assertion.recipient == "https://sp.example.com/acs"
      assert assertion.issuer == "https://idp.example.com"
      assert assertion.subject.name == "jane@example.com"
    end
  end

  # ---------------------------------------------------------------------------
  # Core.Saml.decode_assertion/1 -> from_core/1
  #
  # Guards the seam between the two: the decoder emits binaries, so a
  # multi-valued attribute must survive stringification as a list.
  # ---------------------------------------------------------------------------

  describe "decoding a multi-valued attribute end to end" do
    @tag :decode
    test "exposes every AttributeValue of a multi-valued attribute" do
      xml =
        ~s(<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
          ~s(Version="2.0" IssueInstant="test">) <>
          ~s(<saml:Subject>) <>
          ~s(<saml:NameID>jane@example.com</saml:NameID>) <>
          ~s(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">) <>
          ~s(<saml:SubjectConfirmationData Recipient="https://sp.example.com/acs" />) <>
          ~s(</saml:SubjectConfirmation>) <>
          ~s(</saml:Subject>) <>
          ~s(<saml:AttributeStatement>) <>
          ~s(<saml:Attribute Name="group">) <>
          ~s(<saml:AttributeValue>Admins</saml:AttributeValue>) <>
          ~s(<saml:AttributeValue>Developers</saml:AttributeValue>) <>
          ~s(<saml:AttributeValue>Finance</saml:AttributeValue>) <>
          ~s(</saml:Attribute>) <>
          ~s(</saml:AttributeStatement>) <>
          ~s(</saml:Assertion>)

      assert {:ok, core} = Core.Saml.decode_assertion(parse_xml(xml))
      assert %Assertion{attributes: %{"group" => group}} = Assertion.from_core(core)

      assert Enum.sort(group) == ["Admins", "Developers", "Finance"]
    end
  end
end
