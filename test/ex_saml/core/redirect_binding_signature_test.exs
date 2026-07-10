defmodule ExSaml.Core.RedirectBindingSignatureTest do
  use ExUnit.Case, async: true

  require Record

  alias ExSaml.Core.RedirectBindingSignature

  @rsa_sha1 "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

  # Deflated+Base64 payload content is opaque to the signature scheme; any
  # Base64-looking blob (with `+`/`/`/`=` needing URL encoding) exercises it.
  @payload Base.encode64("<samlp:LogoutRequest ID=\"_x\"/>" <> <<0xFB, 0xEF, 0xBE>>)

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

  # A syntactically valid certificate whose key does NOT match `test_key/0`,
  # taken from the unrelated IdP metadata fixture.
  defp other_cert_der do
    [_, b64] =
      Regex.run(~r/X509Certificate[^>]*>([^<]+)</, File.read!("test/data/idp_metadata.xml"))

    b64 |> String.replace(~r/\s/, "") |> Base.decode64!()
  end

  # Builds a signed Redirect binding query string the way an IdP does
  # (SAML 2.0 Bindings §3.4.4.1): URL-encode each part, concatenate in
  # canonical order, sign, then append the URL-encoded Base64 signature.
  defp signed_query(opts \\ []) do
    type = Keyword.get(opts, :type, "SAMLRequest")
    relay_state = Keyword.get(opts, :relay_state, "some relay/state+chars")
    sig_alg = Keyword.get(opts, :sig_alg, @rsa_sha256)
    digest = Keyword.get(opts, :digest, :sha256)

    query =
      "#{type}=#{URI.encode_www_form(@payload)}" <>
        if(relay_state, do: "&RelayState=#{URI.encode_www_form(relay_state)}", else: "") <>
        "&SigAlg=#{URI.encode_www_form(sig_alg)}"

    signature = :public_key.sign(query, digest, test_key())

    query <> "&Signature=#{URI.encode_www_form(Base.encode64(signature))}"
  end

  describe "verify/2 success cases" do
    test "verifies an rsa-sha256 signed LogoutRequest query" do
      assert :ok = RedirectBindingSignature.verify(signed_query(), [test_cert_der()])
    end

    test "verifies an rsa-sha1 signed query" do
      query = signed_query(sig_alg: @rsa_sha1, digest: :sha)

      assert :ok = RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "verifies a query without RelayState" do
      query = signed_query(relay_state: nil)

      assert :ok = RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "verifies a SAMLResponse payload" do
      query = signed_query(type: "SAMLResponse")

      assert :ok = RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "verifies regardless of parameter order on the wire" do
      # Some senders put Signature/SigAlg first; the signed data must still be
      # rebuilt in canonical order from the raw values.
      parts = String.split(signed_query(), "&")
      reordered = parts |> Enum.reverse() |> Enum.join("&")

      assert :ok = RedirectBindingSignature.verify(reordered, [test_cert_der()])
    end

    test "succeeds when any one of multiple certificates matches (rotation)" do
      certs = [other_cert_der(), test_cert_der()]

      assert :ok = RedirectBindingSignature.verify(signed_query(), certs)
    end

    test "skips undecodable certificates and still verifies with a later one" do
      certs = ["not a certificate", test_cert_der()]

      assert :ok = RedirectBindingSignature.verify(signed_query(), certs)
    end
  end

  describe "verify/2 rejection cases" do
    test "rejects a tampered payload" do
      query =
        String.replace(
          signed_query(),
          "SAMLRequest=",
          "SAMLRequest=#{URI.encode_www_form(Base.encode64("forged"))}"
        )

      assert {:error, :invalid_signature} =
               RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "rejects a tampered RelayState" do
      query = String.replace(signed_query(), "RelayState=some", "RelayState=evil")

      assert {:error, :invalid_signature} =
               RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "rejects when the signing key matches none of the certificates" do
      assert {:error, :invalid_signature} =
               RedirectBindingSignature.verify(signed_query(), [other_cert_der()])
    end

    test "rejects when the certificate list is empty" do
      assert {:error, :invalid_signature} = RedirectBindingSignature.verify(signed_query(), [])
    end

    test "rejects a malformed Base64 signature" do
      query = Regex.replace(~r/Signature=.*$/, signed_query(), "Signature=%25%25not-base64")

      assert {:error, :invalid_signature} =
               RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "rejects when the Signature parameter is missing" do
      query = Regex.replace(~r/&Signature=.*$/, signed_query(), "")

      assert {:error, :missing_signature} =
               RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "rejects when the SigAlg parameter is missing" do
      query = String.replace(signed_query(), ~r/&SigAlg=[^&]*/, "")

      assert {:error, :missing_signature} =
               RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "rejects when no SAMLRequest/SAMLResponse payload is present" do
      query = String.replace(signed_query(), ~r/^SAMLRequest=[^&]*&/, "")

      assert {:error, :missing_signature} =
               RedirectBindingSignature.verify(query, [test_cert_der()])
    end

    test "rejects an unsupported SigAlg URI" do
      unsupported = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
      query = signed_query(sig_alg: unsupported)

      assert {:error, :unsupported_sig_alg} =
               RedirectBindingSignature.verify(query, [test_cert_der()])
    end
  end
end
