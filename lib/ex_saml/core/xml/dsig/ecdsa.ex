defmodule ExSaml.Core.Xml.Dsig.Ecdsa do
  @moduledoc """
  ECDSA signatures for XML-DSig: `ecdsa-sha256`, `ecdsa-sha384` and
  `ecdsa-sha512` on the P-256, P-384 and P-521 curves, and on no other curve,
  when signing as when verifying.

  An ECDSA `SignatureValue` is the raw `r || s` concatenation (RFC 4051
  §3.3.6), each half left-padded to the curve's field size, whereas
  `:public_key` produces and expects the DER `ECDSA-Sig-Value`. This module
  converts both ways, and rejects a `SignatureValue` of another length than
  twice the field size.
  """

  @behaviour ExSaml.Core.Xml.Dsig.KeyAlgorithm

  require Record

  Record.defrecord(
    :ec_private_key,
    :ECPrivateKey,
    Record.extract(:ECPrivateKey, from_lib: "public_key/include/public_key.hrl")
  )

  # id-ecPublicKey, the SubjectPublicKeyInfo algorithm of an EC certificate.
  @ec_public_key {1, 2, 840, 10_045, 2, 1}

  # Bytes of r and s, each, in a signature value, per named curve:
  # secp256r1 (P-256), secp384r1 (P-384) and secp521r1 (P-521).
  @field_sizes %{
    {1, 2, 840, 10_045, 3, 1, 7} => 32,
    {1, 3, 132, 0, 34} => 48,
    {1, 3, 132, 0, 35} => 66
  }

  @impl true
  def spki_algorithm, do: @ec_public_key

  @impl true
  def private_key?(key), do: Record.is_record(key, :ECPrivateKey)

  @doc """
  Signs `data` with an `ECPrivateKey` on a supported curve and returns the
  `SignatureValue` bytes, `r || s`.
  """
  @impl true
  def sign(data, hash, ec_private_key(parameters: parameters) = key) do
    size =
      field_size(parameters) ||
        raise ArgumentError,
              "unsupported EC curve #{inspect(parameters)}, expected P-256, P-384 or P-521"

    der = :public_key.sign(data, hash, key)
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>>
  end

  def sign(_data, _hash, _key), do: raise(ArgumentError, "not an EC private key")

  @doc """
  Verifies the `r || s` `SignatureValue` bytes against an EC public key.

  A key on another curve than P-256, P-384 or P-521, a point the curve does
  not hold, a signature of another length than twice the curve's field size,
  or any other kind of key, such as the RSA key of a certificate whose
  signature method claims `ecdsa-sha256`, fails verification.
  """
  @impl true
  def verify(data, hash, signature, {{:ECPoint, _}, parameters} = key) do
    with size when is_integer(size) <- field_size(parameters),
         <<r::size(size)-unit(8), s::size(size)-unit(8)>> <- signature do
      der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
      :public_key.verify(data, hash, der, key)
    else
      _ -> false
    end
  rescue
    # crypto refuses a point that is not on the curve.
    ErlangError -> false
  end

  def verify(_data, _hash, _signature, _key), do: false

  @doc """
  The EC public key of a certificate, from the curve `parameters` and the
  `subjectPublicKey` point of its `SubjectPublicKeyInfo`, provided the curve
  is P-256, P-384 or P-521 and the point is uncompressed, of the curve's size.

  Depending on the OTP version, a `:plain` certificate's curve parameters come
  DER-encoded or already decoded; both are handled.
  """
  @impl true
  def public_key(parameters, point) when is_binary(parameters) do
    public_key(:public_key.der_decode(:EcpkParameters, parameters), point)
  rescue
    # :public_key.der_decode/2 raises a MatchError on DER it cannot decode.
    MatchError -> :error
  end

  def public_key(parameters, <<4, coordinates::binary>> = point) do
    size = field_size(parameters)

    if size && byte_size(coordinates) == 2 * size,
      do: {:ok, {{:ECPoint, point}, parameters}},
      else: :error
  end

  def public_key(_parameters, _point), do: :error

  # The field size of a supported named curve, nil for any other parameters.
  defp field_size({:namedCurve, curve}), do: Map.get(@field_sizes, curve)
  defp field_size(_parameters), do: nil
end
