defmodule ExSaml.Core.Xml.Dsig.Ecdsa do
  @moduledoc """
  ECDSA signatures for XML-DSig: `ecdsa-sha256`, `ecdsa-sha384` and
  `ecdsa-sha512` on the P-256, P-384 and P-521 curves.

  An ECDSA `SignatureValue` is the raw `r || s` concatenation (RFC 4051
  §3.3.6), each half left-padded to the curve's field size, whereas
  `:public_key` produces and expects the DER `ECDSA-Sig-Value`. This module
  converts both ways.
  """

  require Record

  Record.defrecord(
    :ec_private_key,
    :ECPrivateKey,
    Record.extract(:ECPrivateKey, from_lib: "public_key/include/public_key.hrl")
  )

  # Bytes of r and s, each, in a signature value, per named curve:
  # secp256r1 (P-256), secp384r1 (P-384) and secp521r1 (P-521).
  @field_sizes %{
    {1, 2, 840, 10_045, 3, 1, 7} => 32,
    {1, 3, 132, 0, 34} => 48,
    {1, 3, 132, 0, 35} => 66
  }

  @type hash :: :sha256 | :sha384 | :sha512

  @doc """
  Signs `data` with an `ECPrivateKey` on a supported curve and returns the
  `SignatureValue` bytes, `r || s`.
  """
  @spec sign(binary(), hash(), tuple()) :: binary()
  def sign(data, hash, ec_private_key(parameters: {:namedCurve, curve}) = key) do
    size = Map.fetch!(@field_sizes, curve)
    der = :public_key.sign(data, hash, key)
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>>
  end

  @doc """
  Verifies the `r || s` `SignatureValue` bytes against an EC public key.

  A signature that cannot be two halves, or any other kind of key, such as
  the RSA key of a certificate whose signature method claims `ecdsa-sha256`,
  fails verification.
  """
  @spec verify(binary(), hash(), binary(), term()) :: boolean()
  def verify(data, hash, signature, {{:ECPoint, _}, _} = key)
      when signature != <<>> and rem(byte_size(signature), 2) == 0 do
    size = div(byte_size(signature), 2)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>> = signature
    der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
    :public_key.verify(data, hash, der, key)
  end

  def verify(_data, _hash, _signature, _key), do: false

  @doc """
  The EC public key of a certificate, from the curve `parameters` and the
  `subjectPublicKey` point of its `SubjectPublicKeyInfo`.

  Depending on the OTP version, a `:plain` certificate's curve parameters come
  DER-encoded or already decoded; both are handled.
  """
  @spec public_key(binary() | tuple(), binary()) :: tuple()
  def public_key(parameters, point) when is_binary(parameters),
    do: {{:ECPoint, point}, :public_key.der_decode(:EcpkParameters, parameters)}

  def public_key(parameters, point), do: {{:ECPoint, point}, parameters}
end
