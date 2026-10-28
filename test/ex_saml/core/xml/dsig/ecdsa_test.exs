defmodule ExSaml.Core.Xml.Dsig.EcdsaTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.Dsig.Ecdsa

  @data "<ds:SignedInfo>canonical bytes</ds:SignedInfo>"

  defp ec_key(curve) do
    {:ECPrivateKey, _, _, params, point, _} = key = :public_key.generate_key({:namedCurve, curve})
    {key, {{:ECPoint, point}, params}}
  end

  for {curve, hash, field_size} <- [
        {:secp256r1, :sha256, 32},
        {:secp384r1, :sha384, 48},
        {:secp521r1, :sha512, 66}
      ] do
    test "#{curve}: signs r || s of #{2 * field_size} bytes and verifies it" do
      {key, public_key} = ec_key(unquote(curve))
      signature = Ecdsa.sign(@data, unquote(hash), key)

      assert byte_size(signature) == 2 * unquote(field_size)
      assert Ecdsa.verify(@data, unquote(hash), signature, public_key)
    end
  end

  test "a signature over other data, or with r and s swapped, fails" do
    {key, public_key} = ec_key(:secp256r1)
    <<r::binary-size(32), s::binary-size(32)>> = signature = Ecdsa.sign(@data, :sha256, key)

    refute Ecdsa.verify(@data <> " ", :sha256, signature, public_key)
    refute Ecdsa.verify(@data, :sha256, s <> r, public_key)
  end

  test "a signature that is not two halves fails without raising" do
    {key, public_key} = ec_key(:secp256r1)
    signature = Ecdsa.sign(@data, :sha256, key)

    refute Ecdsa.verify(@data, :sha256, <<>>, public_key)
    refute Ecdsa.verify(@data, :sha256, binary_part(signature, 0, 63), public_key)
  end

  # P-521 values are 521 bits: half of them fit in 65 bytes and must be
  # left-padded to 66.
  test "r and s are left-padded to the field size" do
    {key, public_key} = ec_key(:secp521r1)

    for _ <- 1..20 do
      signature = Ecdsa.sign(@data, :sha512, key)

      assert byte_size(signature) == 132
      assert Ecdsa.verify(@data, :sha512, signature, public_key)
    end
  end

  test "a signature only verifies with the hash it was made with" do
    {key, public_key} = ec_key(:secp384r1)

    for signed_with <- [:sha256, :sha384, :sha512],
        verified_with <- [:sha256, :sha384, :sha512],
        signed_with != verified_with do
      signature = Ecdsa.sign(@data, signed_with, key)

      refute Ecdsa.verify(@data, verified_with, signature, public_key),
             "signed with #{signed_with}, verified with #{verified_with}"
    end
  end

  test "a key on another curve, or another key on the same curve, fails" do
    {key, _} = ec_key(:secp256r1)
    {_, other_curve} = ec_key(:secp384r1)
    {_, same_curve} = ec_key(:secp256r1)
    signature = Ecdsa.sign(@data, :sha256, key)

    refute Ecdsa.verify(@data, :sha256, signature, other_curve)
    refute Ecdsa.verify(@data, :sha256, signature, same_curve)
  end

  test "an RSA private key cannot sign" do
    rsa_key = :public_key.generate_key({:rsa, 2048, 65_537})

    assert_raise FunctionClauseError, fn -> Ecdsa.sign(@data, :sha256, rsa_key) end
  end

  test "a key of another kind fails" do
    {key, _} = ec_key(:secp256r1)
    signature = Ecdsa.sign(@data, :sha256, key)

    {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
      :public_key.generate_key({:rsa, 2048, 65_537})

    refute Ecdsa.verify(@data, :sha256, signature, {:RSAPublicKey, n, e})
  end

  test "an unsupported curve cannot sign" do
    {key, _} = ec_key(:secp256k1)

    assert_raise KeyError, fn -> Ecdsa.sign(@data, :sha256, key) end
  end

  test "public_key/2 takes the curve parameters DER-encoded or decoded" do
    {_, {{:ECPoint, point}, {:namedCurve, _} = params}} = ec_key(:secp256r1)
    params_der = :public_key.der_encode(:EcpkParameters, params)

    assert Ecdsa.public_key(params_der, point) == {{:ECPoint, point}, params}
    assert Ecdsa.public_key(params, point) == {{:ECPoint, point}, params}
  end
end
