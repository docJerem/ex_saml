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

    refute Ecdsa.private_key?(rsa_key)

    assert_raise ArgumentError, ~r/not an EC private key/, fn ->
      Ecdsa.sign(@data, :sha256, rsa_key)
    end
  end

  test "private_key?/1 recognises an ECPrivateKey" do
    {key, public_key} = ec_key(:secp384r1)

    assert Ecdsa.private_key?(key)
    refute Ecdsa.private_key?(public_key)
    refute Ecdsa.private_key?(nil)
  end

  # Curves outside P-256, P-384 and P-521, with their field size.
  for {curve, field_size} <- [secp256k1: 32, brainpoolP256r1: 32, secp224r1: 28] do
    test "a genuine signature by a key on #{curve} fails" do
      {key, public_key} = ec_key(unquote(curve))
      der = :public_key.sign(@data, :sha256, key)
      {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
      signature = <<r::size(unquote(field_size))-unit(8), s::size(unquote(field_size))-unit(8)>>

      refute Ecdsa.verify(@data, :sha256, signature, public_key)
    end
  end

  test "r and s must each be the field size, even zero-padded" do
    {key, public_key} = ec_key(:secp256r1)
    <<r::binary-size(32), s::binary-size(32)>> = signature = Ecdsa.sign(@data, :sha256, key)

    assert Ecdsa.verify(@data, :sha256, signature, public_key)
    refute Ecdsa.verify(@data, :sha256, <<0>> <> r <> <<0>> <> s, public_key)
    refute Ecdsa.verify(@data, :sha256, signature <> <<0, 0>>, public_key)
  end

  test "malformed curve parameters or points fail without raising" do
    {key, {{:ECPoint, point}, params}} = ec_key(:secp256r1)
    signature = Ecdsa.sign(@data, :sha256, key)
    <<4, x::binary-size(32), y::binary-size(32)>> = point
    off_curve = <<4, x::binary, :crypto.exor(y, <<1::256>>)::binary>>

    for public_key <- [
          {{:ECPoint, point}, {:namedCurve, {1, 2, 3, 4}}},
          {{:ECPoint, point}, {:namedCurve, {1, 3, 101, 112}}},
          {{:ECPoint, point}, :asn1_NOVALUE},
          {{:ECPoint, point}, {:implicitlyCA, :NULL}},
          {{:ECPoint, <<>>}, params},
          {{:ECPoint, <<1, 2, 3>>}, params},
          {{:ECPoint, off_curve}, params}
        ] do
      refute Ecdsa.verify(@data, :sha256, signature, public_key), inspect(public_key)
    end
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

    assert_raise ArgumentError, ~r/unsupported EC curve/, fn ->
      Ecdsa.sign(@data, :sha256, key)
    end
  end

  for curve <- [:secp256r1, :secp384r1, :secp521r1] do
    test "public_key/2 takes the #{curve} parameters DER-encoded or decoded" do
      {_, {{:ECPoint, point}, {:namedCurve, _} = params}} = ec_key(unquote(curve))
      params_der = :public_key.der_encode(:EcpkParameters, params)

      assert Ecdsa.public_key(params_der, point) == {:ok, {{:ECPoint, point}, params}}
      assert Ecdsa.public_key(params, point) == {:ok, {{:ECPoint, point}, params}}
    end
  end

  test "public_key/2 is :error for another curve, malformed parameters or point" do
    {_, {{:ECPoint, point}, params}} = ec_key(:secp256r1)
    {_, {{:ECPoint, k1_point}, k1_params}} = ec_key(:secp256k1)
    <<4, x::binary-size(32), _y::binary>> = point

    assert Ecdsa.public_key(k1_params, k1_point) == :error

    assert Ecdsa.public_key(:public_key.der_encode(:EcpkParameters, k1_params), k1_point) ==
             :error

    assert Ecdsa.public_key({:namedCurve, {1, 2, 3, 4}}, point) == :error
    assert Ecdsa.public_key({:implicitlyCA, :NULL}, point) == :error
    assert Ecdsa.public_key(:asn1_NOVALUE, point) == :error
    assert Ecdsa.public_key(<<1, 2, 3>>, point) == :error
    assert Ecdsa.public_key(params, <<2, x::binary>>) == :error
    assert Ecdsa.public_key(params, binary_part(point, 0, 64)) == :error
    assert Ecdsa.public_key(params, <<>>) == :error
  end
end
