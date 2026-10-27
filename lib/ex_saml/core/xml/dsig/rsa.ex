defmodule ExSaml.Core.Xml.Dsig.Rsa do
  @moduledoc """
  RSA signatures for XML-DSig: `rsa-sha1` and `rsa-sha256`.

  The `SignatureValue` is the PKCS#1 v1.5 signature exactly as
  `:public_key.sign/3` returns it, so no conversion is needed either way.
  `rsa-sha1` can still be produced, for legacy peers, but `ExSaml.Core.Xml.Dsig`
  rejects it on verification.
  """

  @type hash :: :sha | :sha256

  @doc """
  Signs `data` and returns the `SignatureValue` bytes.
  """
  @spec sign(binary(), hash(), tuple()) :: binary()
  def sign(data, hash, {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key),
    do: :public_key.sign(data, hash, key)

  @doc """
  Verifies the `SignatureValue` bytes against an RSA public key.

  Any other kind of key, such as the EC key of a certificate whose signature
  method claims `rsa-sha256`, fails verification.
  """
  @spec verify(binary(), hash(), binary(), term()) :: boolean()
  def verify(data, hash, signature, {:RSAPublicKey, _, _} = key),
    do: :public_key.verify(data, hash, signature, key)

  def verify(_data, _hash, _signature, _key), do: false

  @doc """
  The `RSAPublicKey` of a certificate, from the DER `subjectPublicKey` of its
  `SubjectPublicKeyInfo`.
  """
  @spec public_key(binary()) :: tuple()
  def public_key(key_der),
    do: :public_key.pem_entry_decode({:RSAPublicKey, key_der, :not_encrypted})
end
