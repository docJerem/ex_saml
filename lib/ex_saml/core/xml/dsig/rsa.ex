defmodule ExSaml.Core.Xml.Dsig.Rsa do
  @moduledoc """
  RSA signatures for XML-DSig: `rsa-sha1`, `rsa-sha256`, `rsa-sha384` and
  `rsa-sha512`.

  The `SignatureValue` is the PKCS#1 v1.5 signature exactly as
  `:public_key.sign/3` returns it, so no conversion is needed either way.
  `rsa-sha1` can still be produced, for legacy peers, but `ExSaml.Core.Xml.Dsig`
  rejects it on verification.
  """

  @behaviour ExSaml.Core.Xml.Dsig.KeyAlgorithm

  require Record

  Record.defrecord(
    :rsa_private_key,
    :RSAPrivateKey,
    Record.extract(:RSAPrivateKey, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecord(
    :rsa_public_key,
    :RSAPublicKey,
    Record.extract(:RSAPublicKey, from_lib: "public_key/include/public_key.hrl")
  )

  # rsaEncryption, the SubjectPublicKeyInfo algorithm of an RSA certificate.
  @rsa_encryption {1, 2, 840, 113_549, 1, 1, 1}

  @impl true
  def spki_algorithm, do: @rsa_encryption

  @impl true
  def private_key?(key), do: Record.is_record(key, :RSAPrivateKey)

  @doc """
  Signs `data` and returns the `SignatureValue` bytes.
  """
  @impl true
  def sign(data, hash, rsa_private_key() = key), do: :public_key.sign(data, hash, key)

  def sign(_data, _hash, _key), do: raise(ArgumentError, "not an RSA private key")

  @doc """
  Verifies the `SignatureValue` bytes against an RSA public key.

  Any other kind of key, such as the EC key of a certificate whose signature
  method claims `rsa-sha256`, fails verification.
  """
  @impl true
  def verify(data, hash, signature, rsa_public_key() = key),
    do: :public_key.verify(data, hash, signature, key)

  def verify(_data, _hash, _signature, _key), do: false

  @doc """
  The `RSAPublicKey` of a certificate, from the DER `subjectPublicKey` of its
  `SubjectPublicKeyInfo`; the algorithm `parameters` are `NULL` for RSA.
  """
  @impl true
  def public_key(_parameters, key_der) do
    {:ok, :public_key.der_decode(:RSAPublicKey, key_der)}
  rescue
    # :public_key.der_decode/2 raises a MatchError on DER it cannot decode.
    MatchError -> :error
  end
end
