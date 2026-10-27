defmodule ExSaml.Core.Xml.Dsig.MlDsa do
  @moduledoc """
  ML-DSA (FIPS 204) signatures for XML-DSig: `ml-dsa-44`, `ml-dsa-65` and
  `ml-dsa-87`, as draft-eastlake-rfc9231bis-xmlsec-uris-09 §3.3.15 defines
  them.

  The draft uses pure ML-DSA, not HashML-DSA, with the empty context: that
  is what `:public_key.sign/3` and `verify/4` do with the `:none` digest
  type, and it interoperates with OpenSSL's raw ML-DSA signatures. The
  `SignatureValue` is the fixed-length FIPS 204 signature as is, with no
  DER and no conversion.

  `:public_key` knows ML-DSA from OTP 28.1 on, and only when the VM is
  linked with OpenSSL 3.5 or later, so `available?/0` asks the running VM
  rather than an OTP version. The key records, `ML-DSAPrivateKey` and
  `ML-DSAPublicKey`, exist from OTP 28.1 on as well: they are matched as
  tuples, not extracted from `public_key.hrl`, so this module still compiles
  on older OTPs.
  """

  @typedoc "The ML-DSA parameter set, named as `:crypto` names it."
  @type level :: :mldsa44 | :mldsa65 | :mldsa87

  # id-ml-dsa-44, -65 and -87 (NIST CSOR 2.16.840.1.101.3.4.3.{17,18,19}),
  # the SubjectPublicKeyInfo algorithm of an ML-DSA certificate.
  @levels_by_oid %{
    {2, 16, 840, 1, 101, 3, 4, 3, 17} => :mldsa44,
    {2, 16, 840, 1, 101, 3, 4, 3, 18} => :mldsa65,
    {2, 16, 840, 1, 101, 3, 4, 3, 19} => :mldsa87
  }

  @methods %{mldsa44: :ml_dsa_44, mldsa65: :ml_dsa_65, mldsa87: :ml_dsa_87}

  @doc """
  Whether the running VM can sign and verify ML-DSA: OTP 28.1 or later,
  linked with OpenSSL 3.5 or later.
  """
  @spec available?() :: boolean()
  def available?, do: :mldsa65 in :crypto.supports(:public_keys)

  @doc """
  The `SubjectPublicKeyInfo` algorithm OIDs of ML-DSA certificates.
  """
  @spec oids() :: [tuple()]
  def oids, do: Map.keys(@levels_by_oid)

  @doc """
  Signs `data` with an `ML-DSAPrivateKey` and returns the `SignatureValue`
  bytes.

  The key signs with its own parameter set, whatever `level` the signature
  method names: as with the other key types, a mislabelled signature is
  caught on verification, not here.
  """
  @spec sign(binary(), level(), tuple()) :: binary()
  def sign(data, _level, {:"ML-DSAPrivateKey", _, _, _} = key),
    do: :public_key.sign(data, :none, key)

  @doc """
  Verifies the `SignatureValue` bytes against an `ML-DSAPublicKey` of the
  parameter set the signature method names.

  A key of another parameter set, or of another kind, such as the RSA key of
  a certificate whose signature method claims `ml-dsa-65`, fails verification.
  """
  @spec verify(binary(), level(), binary(), term()) :: boolean()
  def verify(data, level, signature, {:"ML-DSAPublicKey", level, _} = key),
    do: :public_key.verify(data, :none, signature, key)

  def verify(_data, _level, _signature, _key), do: false

  @doc """
  The `ML-DSAPublicKey` of a certificate, from the algorithm OID and the
  `subjectPublicKey` bytes of its `SubjectPublicKeyInfo`.
  """
  @spec public_key(tuple(), binary()) :: tuple()
  def public_key(oid, key_bin), do: {:"ML-DSAPublicKey", Map.fetch!(@levels_by_oid, oid), key_bin}

  @doc """
  The signature method matching the key's parameter set.
  """
  @spec default_method(tuple()) :: :ml_dsa_44 | :ml_dsa_65 | :ml_dsa_87
  def default_method({:"ML-DSAPrivateKey", level, _, _}), do: Map.fetch!(@methods, level)
end
