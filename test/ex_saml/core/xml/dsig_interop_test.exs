defmodule ExSaml.Core.Xml.DsigInteropTest do
  # XML-DSig interoperability, checked against a signer and a verifier
  # independent of ExSaml.Core.Xml.Dsig and ExSaml.Core.Xml.C14n: the
  # exclusive canonical forms (https://www.w3.org/TR/xml-exc-c14n/) are written
  # by hand from the specification, and digests and signatures are computed
  # with :crypto and :public_key only. The algorithm URIs are those of
  # RFC 6931, written out rather than read from Dsig.
  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.Dsig

  @xmldsig "http://www.w3.org/2000/09/xmldsig#"
  @exc_c14n "http://www.w3.org/2001/10/xml-exc-c14n#"
  @enveloped "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

  @digests %{
    sha256: "http://www.w3.org/2001/04/xmlenc#sha256",
    sha384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
    sha512: "http://www.w3.org/2001/04/xmlenc#sha512"
  }

  # Signature method: URI, hash, and the key it needs (RSA or a curve).
  @methods %{
    rsa_sha256: {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", :sha256, :rsa},
    rsa_sha384: {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", :sha384, :rsa},
    rsa_sha512: {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", :sha512, :rsa},
    ecdsa_sha256: {"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", :sha256, :secp256r1},
    ecdsa_sha384: {"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", :sha384, :secp384r1},
    ecdsa_sha512: {"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", :sha512, :secp521r1}
  }

  # Bytes of r and s, each, in an ECDSA SignatureValue (RFC 4051 §3.3.6).
  @field_sizes %{secp256r1: 32, secp384r1: 48, secp521r1: 66}

  # A SAML Response as an IdP could send it: indented, an unused namespace
  # declaration, attributes out of order, empty elements, text to escape.
  # `SIGNATURE` marks where the enveloped ds:Signature goes.
  @response """
  <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:unused="urn:unused" \
  Version="2.0" ID="_r1" IssueInstant="2026-10-28T10:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>SIGNATURE
    <samlp:Status>
      <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
      <samlp:StatusMessage>Tom &amp; Jerry > 1</samlp:StatusMessage>
    </samlp:Status>
  </samlp:Response>\
  """

  # Its exclusive canonical form without the signature: only the visibly
  # utilized namespaces, `saml` pushed down to the element that uses it,
  # attributes sorted, empty elements expanded, `>` escaped in text.
  @response_c14n """
  <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
  ID="_r1" IssueInstant="2026-10-28T10:00:00Z" Version="2.0">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
    <samlp:Status>
      <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
      <samlp:StatusMessage>Tom &amp; Jerry &gt; 1</samlp:StatusMessage>
    </samlp:Status>
  </samlp:Response>\
  """

  # The same with `saml` in the InclusiveNamespaces PrefixList: declared on
  # the apex element, in prefix order, and not again on Issuer.
  @response_c14n_saml_inclusive """
  <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" \
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
  ID="_r1" IssueInstant="2026-10-28T10:00:00Z" Version="2.0">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
      <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
      <samlp:StatusMessage>Tom &amp; Jerry &gt; 1</samlp:StatusMessage>
    </samlp:Status>
  </samlp:Response>\
  """

  # --- The independent signer and verifier ---

  defp key(:rsa) do
    %{cert: cert, key: key} =
      :public_key.pkix_test_root_cert(~c"Interop RSA", key: {:rsa, 2048, 65_537})

    {key, cert}
  end

  defp key(curve) do
    %{cert: cert, key: key} =
      :public_key.pkix_test_root_cert(~c"Interop EC", key: {:namedCurve, curve})

    {key, cert}
  end

  # The SignedInfo as it is written in the document: empty elements
  # self-closed, the ds prefix declared on ds:Signature.
  defp signed_info(method_uri, digest_uri, digest_b64, prefix_list) do
    ~s|<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="#{@exc_c14n}"/>| <>
      ~s|<ds:SignatureMethod Algorithm="#{method_uri}"/><ds:Reference URI="#_r1">| <>
      ~s|<ds:Transforms><ds:Transform Algorithm="#{@enveloped}"/>| <>
      exc_c14n_transform(prefix_list, :document) <>
      ~s|</ds:Transforms><ds:DigestMethod Algorithm="#{digest_uri}"/>| <>
      ~s|<ds:DigestValue>#{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>|
  end

  # Its exclusive canonical form, the bytes the SignatureValue covers.
  defp signed_info_c14n(method_uri, digest_uri, digest_b64, prefix_list) do
    ~s|<ds:SignedInfo xmlns:ds="#{@xmldsig}">| <>
      ~s|<ds:CanonicalizationMethod Algorithm="#{@exc_c14n}"></ds:CanonicalizationMethod>| <>
      ~s|<ds:SignatureMethod Algorithm="#{method_uri}"></ds:SignatureMethod>| <>
      ~s|<ds:Reference URI="#_r1"><ds:Transforms>| <>
      ~s|<ds:Transform Algorithm="#{@enveloped}"></ds:Transform>| <>
      exc_c14n_transform(prefix_list, :c14n) <>
      ~s|</ds:Transforms><ds:DigestMethod Algorithm="#{digest_uri}"></ds:DigestMethod>| <>
      ~s|<ds:DigestValue>#{digest_b64}</ds:DigestValue></ds:Reference></ds:SignedInfo>|
  end

  defp exc_c14n_transform(nil, :document), do: ~s|<ds:Transform Algorithm="#{@exc_c14n}"/>|

  defp exc_c14n_transform(nil, :c14n),
    do: ~s|<ds:Transform Algorithm="#{@exc_c14n}"></ds:Transform>|

  defp exc_c14n_transform(prefix_list, :document) do
    ~s|<ds:Transform Algorithm="#{@exc_c14n}">| <>
      ~s|<ec:InclusiveNamespaces xmlns:ec="#{@exc_c14n}" PrefixList="#{prefix_list}"/>| <>
      ~s|</ds:Transform>|
  end

  defp exc_c14n_transform(prefix_list, :c14n) do
    ~s|<ds:Transform Algorithm="#{@exc_c14n}">| <>
      ~s|<ec:InclusiveNamespaces xmlns:ec="#{@exc_c14n}" PrefixList="#{prefix_list}">| <>
      ~s|</ec:InclusiveNamespaces></ds:Transform>|
  end

  defp signature_value(data, hash, key, :rsa), do: :public_key.sign(data, hash, key)

  defp signature_value(data, hash, key, curve) do
    size = Map.fetch!(@field_sizes, curve)
    der = :public_key.sign(data, hash, key)
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>>
  end

  # A Response signed by the independent signer.
  defp signed_response(method, opts \\ []) do
    {method_uri, hash, key_kind} = Map.fetch!(@methods, method)
    digest_hash = Keyword.get(opts, :digest, hash)
    prefix_list = Keyword.get(opts, :prefix_list)
    {key, cert} = key(key_kind)

    reference_c14n = if prefix_list, do: @response_c14n_saml_inclusive, else: @response_c14n
    digest_b64 = Base.encode64(:crypto.hash(digest_hash, reference_c14n))
    digest_uri = Map.fetch!(@digests, digest_hash)

    sig_value =
      method_uri
      |> signed_info_c14n(digest_uri, digest_b64, prefix_list)
      |> signature_value(hash, key, key_kind)

    signature =
      ~s|<ds:Signature xmlns:ds="#{@xmldsig}">| <>
        signed_info(method_uri, digest_uri, digest_b64, prefix_list) <>
        ~s|<ds:SignatureValue>#{Base.encode64(sig_value)}</ds:SignatureValue>| <>
        ~s|<ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{Base.encode64(cert)}| <>
        ~s|</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>|

    {String.replace(@response, "SIGNATURE", signature), cert}
  end

  # Verifies, without Dsig, a document Dsig signed: the DigestValue against
  # the hand-written canonical form, and the SignatureValue against the
  # canonical SignedInfo rebuilt from the RFC 6931 URIs of the method.
  defp independently_verify(xml, method) do
    {method_uri, hash, _key_kind} = Map.fetch!(@methods, method)
    digest_uri = Map.fetch!(@digests, hash)

    [digest_b64] = Regex.run(~r|<ds:DigestValue>([^<]+)<|, xml, capture: :all_but_first)
    [sig_b64] = Regex.run(~r|<ds:SignatureValue>([^<]+)<|, xml, capture: :all_but_first)
    [cert_b64] = Regex.run(~r|<ds:X509Certificate>([^<]+)<|, xml, capture: :all_but_first)

    assert Base.decode64!(digest_b64) == :crypto.hash(hash, @response_c14n)

    signed_info = signed_info_c14n(method_uri, digest_uri, digest_b64, nil)
    sig = Base.decode64!(sig_b64)

    {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, _, _, spki, _, _, _}, _, _} =
      cert_b64 |> Base.decode64!() |> :public_key.pkix_decode_cert(:otp)

    assert verify_signature_value(signed_info, hash, sig, spki)
  end

  defp verify_signature_value(
         data,
         hash,
         sig,
         {:OTPSubjectPublicKeyInfo, _, {:RSAPublicKey, _, _} = key}
       ),
       do: :public_key.verify(data, hash, sig, key)

  defp verify_signature_value(data, hash, sig, {:OTPSubjectPublicKeyInfo, {_, _, params}, point}) do
    size = div(byte_size(sig), 2)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>> = sig
    der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
    :public_key.verify(data, hash, der, {point, params})
  end

  defp parse(xml) do
    {doc, []} =
      xml
      |> String.to_charlist()
      |> :xmerl_scan.string(namespace_conformant: true, allow_entities: false)

    doc
  end

  defp to_xml_string(element),
    do: [element] |> :xmerl.export(:xmerl_xml) |> List.flatten() |> to_string()

  # --- Tests ---

  describe "Dsig.verify/2 on a document signed independently" do
    for method <- [
          :rsa_sha256,
          :rsa_sha384,
          :rsa_sha512,
          :ecdsa_sha256,
          :ecdsa_sha384,
          :ecdsa_sha512
        ] do
      test "#{method}" do
        {xml, cert} = signed_response(unquote(method))

        assert :ok = xml |> parse() |> Dsig.verify([{:sha256, :crypto.hash(:sha256, cert)}])
      end
    end

    test "with an InclusiveNamespaces PrefixList" do
      {xml, _cert} = signed_response(:rsa_sha256, prefix_list: "saml")

      assert :ok = xml |> parse() |> Dsig.verify()
    end

    @tag skip: "the DigestMethod is not read yet, see #72"
    test "with a digest hash other than the signature's: rsa-sha512 over a SHA-256 digest" do
      {xml, _cert} = signed_response(:rsa_sha512, digest: :sha256)

      assert :ok = xml |> parse() |> Dsig.verify()
    end

    test "an altered document is rejected with :bad_digest" do
      {xml, _cert} = signed_response(:ecdsa_sha256)

      assert {:error, :bad_digest} =
               xml
               |> String.replace("Tom &amp; Jerry", "Tom &amp; Spike")
               |> parse()
               |> Dsig.verify()
    end

    test "a certificate not trusted is rejected with :cert_not_accepted" do
      {xml, _cert} = signed_response(:rsa_sha384)
      {_key, other_cert} = key(:rsa)

      assert {:error, :cert_not_accepted} =
               xml |> parse() |> Dsig.verify([{:sha256, :crypto.hash(:sha256, other_cert)}])
    end
  end

  describe "a document signed by Dsig.sign/4, verified independently" do
    for method <- [
          :rsa_sha256,
          :rsa_sha384,
          :rsa_sha512,
          :ecdsa_sha256,
          :ecdsa_sha384,
          :ecdsa_sha512
        ] do
      test "#{method}" do
        {_method_uri, _hash, key_kind} = Map.fetch!(@methods, unquote(method))
        {key, cert} = key(key_kind)

        @response
        |> String.replace("SIGNATURE", "")
        |> parse()
        |> Dsig.sign(key, cert, unquote(method))
        |> to_xml_string()
        |> independently_verify(unquote(method))
      end
    end
  end
end
