defmodule ExSaml.Core.Xml.Dsig.MlDsaTest do
  # The fixtures under test/data/keys are OpenSSL-made: Erlang cannot
  # generate an ML-DSA certificate, and the signatures are randomized, so
  # the tests verify rather than compare bytes.
  use ExUnit.Case, async: true

  @moduletag :ml_dsa

  import ExUnit.CaptureLog

  alias ExSaml.Core.Xml.Dsig
  alias ExSaml.Core.Xml.Dsig.MlDsa

  require Record

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  @keys_dir Path.expand("../../../../data/keys", __DIR__)
  @data "<ds:SignedInfo>canonical bytes</ds:SignedInfo>"
  @ds_ns [{~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}]
  @foo ~S|<x:foo id="test" xmlns:x="urn:foo:x:"><x:name>blah</x:name></x:foo>|

  @levels [
    {44, :mldsa44, :ml_dsa_44, 2420, "http://www.w3.org/2001/04/xmlenc#sha256"},
    {65, :mldsa65, :ml_dsa_65, 3309, "http://www.w3.org/2001/04/xmldsig-more#sha384"},
    {87, :mldsa87, :ml_dsa_87, 4627, "http://www.w3.org/2001/04/xmlenc#sha512"}
  ]

  defp fixture(level) do
    [entry] =
      @keys_dir |> Path.join("ml_dsa_#{level}.pem") |> File.read!() |> :public_key.pem_decode()

    [{:Certificate, cert_der, _}] =
      @keys_dir |> Path.join("ml_dsa_#{level}.crt") |> File.read!() |> :public_key.pem_decode()

    {:public_key.pem_entry_decode(entry), cert_der}
  end

  defp public_key(cert_der) do
    {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, _, _, spki, _, _, _}, _, _} =
      :public_key.pkix_decode_cert(cert_der, :otp)

    {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, oid, _}, key} = spki
    {oid, key}
  end

  defp parse_xml(xml_string) do
    {doc, _} = :xmerl_scan.string(String.to_charlist(xml_string), namespace_conformant: true)
    doc
  end

  defp export(xml), do: [xml] |> :xmerl.export(:xmerl_xml) |> List.flatten() |> to_string()

  defp signed_foo(key, cert_der, method),
    do: @foo |> parse_xml() |> Dsig.sign(key, cert_der, method)

  defp attribute(xml, xpath) do
    [attr] = :xmerl_xpath.string(xpath, xml, namespace: @ds_ns)
    to_string(xmlAttribute(attr, :value))
  end

  defp signature_value(xml) do
    [text] =
      :xmerl_xpath.string(~c"ds:Signature/ds:SignatureValue/text()", xml, namespace: @ds_ns)

    :base64.decode(xmlText(text, :value))
  end

  describe "the module" do
    test "available?/0 is true here" do
      assert MlDsa.available?()
    end

    for {level, algorithm, method, size, _digest_uri} <- @levels do
      test "ML-DSA-#{level}: signs the raw FIPS 204 signature of #{size} bytes and verifies it" do
        {key, cert_der} = fixture(unquote(level))
        {oid, public_key} = public_key(cert_der)
        signature = MlDsa.sign(@data, unquote(algorithm), key)

        assert byte_size(signature) == unquote(size)
        assert MlDsa.verify(@data, unquote(algorithm), signature, public_key)
        assert MlDsa.public_key(oid, elem(public_key, 2)) == public_key
        assert MlDsa.default_method(key) == unquote(method)
      end
    end

    test "a signature over other data, tampered or truncated fails without raising" do
      {key, cert_der} = fixture(65)
      {_, public_key} = public_key(cert_der)
      <<first, rest::binary>> = signature = MlDsa.sign(@data, :mldsa65, key)

      refute MlDsa.verify(@data <> " ", :mldsa65, signature, public_key)
      refute MlDsa.verify(@data, :mldsa65, <<first + 1, rest::binary>>, public_key)
      refute MlDsa.verify(@data, :mldsa65, rest, public_key)
      refute MlDsa.verify(@data, :mldsa65, <<>>, public_key)
    end

    test "a key of another parameter set, or of another kind, fails" do
      {key, cert_der} = fixture(65)
      {_, public_key} = public_key(cert_der)
      signature = MlDsa.sign(@data, :mldsa65, key)

      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
        :public_key.generate_key({:rsa, 2048, 65_537})

      refute MlDsa.verify(@data, :mldsa44, signature, public_key)
      refute MlDsa.verify(@data, :mldsa65, signature, {:RSAPublicKey, n, e})
    end
  end

  describe "through Dsig" do
    for {level, _algorithm, method, size, digest_uri} <- @levels do
      test "#{method}: signs with its URIs, verifies, and is the key's default method" do
        {key, cert_der} = fixture(unquote(level))
        signed = signed_foo(key, cert_der, unquote(method))

        assert attribute(signed, ~c"ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm") ==
                 "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-#{unquote(level)}"

        assert attribute(
                 signed,
                 ~c"ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm"
               ) ==
                 unquote(digest_uri)

        assert byte_size(signature_value(signed)) == unquote(size)
        assert :ok = Dsig.verify(signed, [{:sha256, :crypto.hash(:sha256, cert_der)}])
        assert :ok = signed |> export() |> parse_xml() |> Dsig.verify()

        assert Dsig.default_method(key) == unquote(method)
        assert :ok = @foo |> parse_xml() |> Dsig.sign(key, cert_der) |> Dsig.verify()
      end
    end

    test "the method is also taken by URI" do
      {key, cert_der} = fixture(44)
      uri = "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44"

      assert :ok = key |> signed_foo(cert_der, uri) |> Dsig.verify()
    end

    test "a tampered signature is rejected" do
      {key, cert_der} = fixture(65)
      xml = key |> signed_foo(cert_der, :ml_dsa_65) |> export()
      [sig64] = Regex.run(~r|<ds:SignatureValue>([^<]+)<|, xml, capture: :all_but_first)
      <<first, rest::binary>> = :base64.decode(sig64)
      tampered = :base64.encode(<<first + 1, rest::binary>>)

      assert {:error, :bad_signature} =
               xml |> String.replace(sig64, tampered) |> parse_xml() |> Dsig.verify()
    end

    test "a method of another parameter set than the certificate's is rejected" do
      {key, cert_der} = fixture(44)

      assert {:error, :bad_signature} = key |> signed_foo(cert_der, :ml_dsa_65) |> Dsig.verify()
    end

    test "a method of another key type than the certificate's is rejected" do
      {ml_dsa_key, ml_dsa_cert} = fixture(65)

      %{cert: rsa_cert, key: rsa_key} =
        :public_key.pkix_test_root_cert(~c"ExSaml RSA", key: {:rsa, 2048, 65_537})

      # An RSA signature relabelled ml-dsa-65: its SHA-256 DigestMethod is
      # one ML-DSA accepts, so it gets as far as the key check.
      relabelled =
        rsa_key
        |> signed_foo(rsa_cert, :rsa_sha256)
        |> export()
        |> String.replace(
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65"
        )
        |> parse_xml()

      assert {:error, :bad_signature} = Dsig.verify(relabelled)

      assert {:error, :bad_signature} =
               ml_dsa_key |> signed_foo(ml_dsa_cert, :rsa_sha256) |> Dsig.verify()
    end

    test "the Reference digest is the one DigestMethod names" do
      {key, cert_der} = fixture(65)
      xml = key |> signed_foo(cert_der, :ml_dsa_65) |> export()
      sha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
      assert xml =~ sha384

      # The stored digest is SHA-384: computing SHA-256 instead cannot match.
      assert {:error, :bad_digest} =
               xml
               |> String.replace(sha384, "http://www.w3.org/2001/04/xmlenc#sha256")
               |> parse_xml()
               |> Dsig.verify()

      log =
        capture_log(fn ->
          assert {:error, :unsupported_algorithm} =
                   xml
                   |> String.replace(sha384, "http://www.w3.org/2000/09/xmldsig#sha1")
                   |> parse_xml()
                   |> Dsig.verify()
        end)

      assert log =~ "Unsupported digest algorithm"
    end

    test "a SignatureContext is rejected rather than ignored" do
      {key, cert_der} = fixture(65)
      xml = key |> signed_foo(cert_der, :ml_dsa_65) |> export()

      context =
        ~S|<ds:Object><SignatureContext xmlns="http://www.w3.org/2026/08/xmldsig-more#">ctx</SignatureContext></ds:Object></ds:Signature>|

      log =
        capture_log(fn ->
          assert {:error, :unsupported_algorithm} =
                   xml
                   |> String.replace("</ds:Signature>", context)
                   |> parse_xml()
                   |> Dsig.verify()
        end)

      assert log =~ "SignatureContext"
    end
  end
end
