defmodule ExSaml.Core.Xml.Dsig.KeyAlgorithm do
  @moduledoc """
  The behaviour of the module of one key type, such as
  `ExSaml.Core.Xml.Dsig.Rsa` or `ExSaml.Core.Xml.Dsig.Ecdsa`.

  `ExSaml.Core.Xml.Dsig` owns the XML side and asks the module for the
  `SignatureValue` bytes only. It picks the module from the private key when
  signing, and when verifying from the signature method, which must name the
  same module as the algorithm of the certificate's `SubjectPublicKeyInfo`.

  Verification must never raise on what a document carries: a key or a
  signature the module cannot use is `:error` or `false`.
  """

  @typedoc """
  The hash of the signature method. A scheme that signs the message itself,
  rather than its hash, may ignore it.
  """
  @type hash :: :sha | :sha256 | :sha384 | :sha512

  @doc """
  The `AlgorithmIdentifier` OID of a certificate's `SubjectPublicKeyInfo`
  holding a key of this type.
  """
  @callback spki_algorithm() :: tuple()

  @doc """
  Whether `key` is a private key of this type.
  """
  @callback private_key?(key :: term()) :: boolean()

  @doc """
  Signs `data` and returns the `SignatureValue` bytes. Raises an
  `ArgumentError` for a private key the module cannot sign with.
  """
  @callback sign(data :: binary(), hash(), private_key :: tuple()) :: binary()

  @doc """
  Verifies the `SignatureValue` bytes against a public key read by
  `c:public_key/2`. Any other key, or a malformed signature, is `false`.
  """
  @callback verify(data :: binary(), hash(), signature :: binary(), public_key :: term()) ::
              boolean()

  @doc """
  The public key of a certificate, from the `parameters` of its
  `SubjectPublicKeyInfo` algorithm and its `subjectPublicKey` bits, or
  `:error` when the module does not support it.
  """
  @callback public_key(parameters :: term(), key_bits :: binary()) :: {:ok, term()} | :error
end
