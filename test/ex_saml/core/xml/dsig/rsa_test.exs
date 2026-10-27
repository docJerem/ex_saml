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

  test "a key of another kind fails", %{key: key} do
    signature = Rsa.sign(@data, :sha256, key)

    {{:ECPoint, _}, _} =
      ec_key = :public_key.generate_key({:namedCurve, :secp256r1}) |> ec_public()

    refute Rsa.verify(@data, :sha256, signature, ec_key)
  end

  test "public_key/1 reads the certificate's RSAPublicKey" do
    %{cert: cert_der} = :public_key.pkix_test_root_cert(~c"ExSaml RSA", key: {:rsa, 2048, 65_537})

    {:OTPCertificate, {:OTPTBSCertificate, _, _, _, _, _, _, spki, _, _, _}, _, _} =
      :public_key.pkix_decode_cert(cert_der, :otp)

    {:OTPSubjectPublicKeyInfo, _, {:RSAPublicKey, n, e}} = spki
    key_der = :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, n, e})

    assert Rsa.public_key(key_der) == {:RSAPublicKey, n, e}
  end

  defp ec_public({:ECPrivateKey, _, _, params, point, _}), do: {{:ECPoint, point}, params}
end
