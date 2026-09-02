defmodule ExSaml.Core.SpValidateAssertionTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.Core.{Sp, SpConfig}
  alias ExSaml.{Debug, StubCache}

  @ns ~s(xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion")

  setup do
    StubCache.install()
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_saml_sub_status: nil, ex_saml_idp_id: nil, ex_saml_debug_id: nil)
    :ok
  end

  defp sp do
    %SpConfig{
      metadata_uri: "https://sp.example.com/metadata",
      consume_uri: "https://sp.example.com/consume",
      idp_signs_envelopes: false,
      idp_signs_assertions: false
    }
  end

  defp parse(xml) do
    {doc, _} =
      xml
      |> :binary.bin_to_list()
      |> :xmerl_scan.string(namespace_conformant: true, allow_entities: false)

    doc
  end

  defp response(status_block) do
    parse("""
    <samlp:Response #{@ns} ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
      #{status_block}
    </samlp:Response>
    """)
  end

  describe "IdP status errors" do
    test "Responder with nested AuthnFailed: public tuple unchanged, nested status recorded" do
      xml =
        response("""
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>
          </samlp:StatusCode>
          <samlp:StatusMessage>User could not be authenticated</samlp:StatusMessage>
        </samlp:Status>
        """)

      assert {:error, {:saml_error, status, message}} = Sp.validate_assertion(xml, sp())
      assert to_string(status) == "urn:oasis:names:tc:SAML:2.0:status:Responder"
      assert to_string(message) == "User could not be authenticated"

      assert Logger.metadata()[:ex_saml_saml_sub_status] == :authn_failed

      error = ExSaml.Error.new(%{reason: {:saml_error, status, message}})
      assert error.saml_status == :responder
      assert error.saml_sub_status == :authn_failed
      assert ExSaml.ErrorMessages.get(error) =~ "AuthnFailed"
    end

    test "Requester without nested code" do
      xml =
        response("""
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
        </samlp:Status>
        """)

      assert {:error, {:saml_error, _status, nil}} = Sp.validate_assertion(xml, sp())
      assert Logger.metadata()[:ex_saml_saml_sub_status] == nil
    end

    test "logs the full status in debug mode" do
      Application.put_env(:ex_saml, :debug, true)

      xml =
        response("""
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"/>
          </samlp:StatusCode>
        </samlp:Status>
        """)

      log = capture_log(fn -> Sp.validate_assertion(xml, sp()) end)
      assert log =~ "[ExSaml.Debug] saml_status_error"
      assert log =~ "sub_status: :invalid_nameid_policy"
      assert log =~ "[ExSaml.Debug] validate_assertion_failed"
    end
  end

  describe "extraction failures" do
    test "no Assertion -> :bad_assertion, with the swallowed cause in debug mode" do
      xml =
        response("""
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        """)

      log =
        capture_log(fn -> assert {:error, :bad_assertion} = Sp.validate_assertion(xml, sp()) end)

      refute log =~ "[ExSaml.Debug]"

      Debug.enable()

      log =
        capture_log(fn -> assert {:error, :bad_assertion} = Sp.validate_assertion(xml, sp()) end)

      assert log =~ "where: :assertion_count"
      assert log =~ "count: 0"
    end

    test "no Status -> :bad_saml" do
      xml = response("")
      assert {:error, :bad_saml} = Sp.validate_assertion(xml, sp())
    end
  end

  describe "signature failures" do
    test "tampered envelope signature -> {:envelope, {:error, :bad_signature}}, with a message" do
      xml = File.read!(Path.join([__DIR__, "../fixtures/sha256_signed_response.xml"]))
      [_, sig] = Regex.run(~r|<ds:SignatureValue>([^<]+)</ds:SignatureValue>|, xml)
      flipped = if String.first(sig) == "A", do: "B", else: "A"
      tampered_sig = flipped <> String.slice(sig, 1..-1//1)

      tampered =
        String.replace(xml, "<ds:SignatureValue>#{sig}", "<ds:SignatureValue>#{tampered_sig}")

      sp = %{sp() | idp_signs_envelopes: true, trusted_fingerprints: :any}

      assert {:error, {:envelope, {:error, :bad_signature}} = reason} =
               Sp.validate_assertion(parse(tampered), sp)

      assert ExSaml.ErrorMessages.get(reason) =~ "signature could not be verified"
      assert ExSaml.ErrorMessages.get(reason, "fr") =~ "signature SAML n'a pas pu être vérifiée"
    end
  end
end
