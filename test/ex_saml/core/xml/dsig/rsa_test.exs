defmodule ExSaml.Core.Xml.Dsig.RsaTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.Dsig.Rsa

  @data "<ds:SignedInfo>canonical bytes</ds:SignedInfo>"

  setup_all do
    {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
      key = :public_key.generate_key({:rsa, 2048, 65_537})

    %{key: key, public_key: {:RSAPublicKey, n, e}}
  end

  test "signs and verifies with the key's public half", %{key: key, public_key: public_key} do
    signature = Rsa.sign(@data, :sha256, key)

    assert byte_size(signature) == 256
    assert Rsa.verify(@data, :sha256, signature, public_key)
  end

  test "a signature over other data, or tampered, fails", %{key: key, public_key: public_key} do
    signature = Rsa.sign(@data, :sha256, key)
    <<first, rest::binary>> = signature

    refute Rsa.verify(@data <> " ", :sha256, signature, public_key)
    refute Rsa.verify(@data, :sha256, <<first + 1, rest::binary>>, public_key)
    refute Rsa.verify(@data, :sha, signature, public_key)
  end

  for hash <- [:sha384, :sha512] do
    test "signs and verifies with #{hash}", %{key: key, public_key: public_key} do
      signature = Rsa.sign(@data, unquote(hash), key)

      assert byte_size(signature) == 256
      assert Rsa.verify(@data, unquote(hash), signature, public_key)
    end
  end

  test "a signature only verifies with the hash it was made with", %{
    key: key,
    public_key: public_key
  } do
    for signed_with <- [:sha256, :sha384, :sha512],
        verified_with <- [:sha256, :sha384, :sha512],
        signed_with != verified_with do
      signature = Rsa.sign(@data, signed_with, key)

      refute Rsa.verify(@data, verified_with, signature, public_key),
             "signed with #{signed_with}, verified with #{verified_with}"
    end
  end

  test "another RSA key fails", %{key: key} do
    signature = Rsa.sign(@data, :sha512, key)

    {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
      :public_key.generate_key({:rsa, 2048, 65_537})

    refute Rsa.verify(@data, :sha512, signature, {:RSAPublicKey, n, e})
  end

  test "an EC private key cannot sign" do
    ec_key = :public_key.generate_key({:namedCurve, :secp256r1})

    refute Rsa.private_key?(ec_key)

    assert_raise ArgumentError, ~r/not an RSA private key/, fn ->
      Rsa.sign(@data, :sha256, ec_key)
    end
  end

  test "private_key?/1 recognises an RSAPrivateKey", %{key: key, public_key: public_key} do
    assert Rsa.private_key?(key)
    refute Rsa.private_key?(public_key)
    refute Rsa.private_key?(nil)
  end

  test "a key of another kind fails", %{key: key} do
    signature = Rsa.sign(@data, :sha256, key)

    {{:ECPoint, _}, _} =
      ec_key = :public_key.generate_key({:namedCurve, :secp256r1}) |> ec_public()

    refute Rsa.verify(@data, :sha256, signature, ec_key)
  end

  test "public_key/2 reads the RSAPublicKey of a certificate's SubjectPublicKeyInfo" do
    %{cert: cert_der, key: {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _}} =
      :public_key.pkix_test_root_cert(~c"ExSaml RSA", key: {:rsa, 2048, 65_537})

    # The bits Dsig reads, from the :plain certificate.
    {:Certificate, {:TBSCertificate, _, _, _, _, _, _, spki, _, _, _}, _, _} =
      :public_key.pkix_decode_cert(cert_der, :plain)

    {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, algorithm, parameters}, key_der} = spki

    assert algorithm == Rsa.spki_algorithm()
    assert Rsa.public_key(parameters, key_der) == {:ok, {:RSAPublicKey, n, e}}
  end

  test "public_key/2 is :error on DER it cannot decode" do
    assert Rsa.public_key(<<5, 0>>, <<>>) == :error
    assert Rsa.public_key(<<5, 0>>, "AAAA") == :error
    assert Rsa.public_key(<<5, 0>>, <<48, 3, 2, 1>>) == :error
  end

  test "a degenerate public key fails without raising", %{key: key} do
    signature = Rsa.sign(@data, :sha256, key)

    for public_key <- [{:RSAPublicKey, 0, 0}, {:RSAPublicKey, 1, 1}, {:RSAPublicKey, 15, 3}] do
      refute Rsa.verify(@data, :sha256, signature, public_key)
    end
  end

  defp ec_public({:ECPrivateKey, _, _, params, point, _}), do: {{:ECPoint, point}, params}
end
