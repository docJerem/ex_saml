defmodule ExSaml.Core.Xml.Enc do
  @moduledoc """
  XML Encryption decryption ([XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/)).

  Decrypts an `xenc:EncryptedData` whose symmetric key is transported, under
  an RSA public key, in an `xenc:EncryptedKey` of its `ds:KeyInfo`.

  - Block ciphers: AES-128, AES-192 and AES-256, in CBC mode (`xmlenc#aesN-cbc`)
    or GCM mode (`xmlenc11#aesN-gcm`).
  - Key transports: `xmlenc#rsa-oaep-mgf1p` and `xmlenc11#rsa-oaep`, with their
    `ds:DigestMethod`, `xenc11:MGF` and `xenc:OAEPparams`. `xmlenc#rsa-1_5` is
    open to Bleichenbacher's attack (XML Encryption 1.1 §5.5.1) and is refused
    unless `allow_rsa_1_5_key_transport: true` is given.

  Every failure returns `{:error, :decryption_failed}`, whatever its cause, so
  that the result does not tell a padding failure from another one. AES-CBC is
  not authenticated: the caller should check a signature over the ciphertext
  before decrypting it.
  """

  require Logger
  require Record

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  @type element :: tuple()
  @type opts :: [allow_rsa_1_5_key_transport: boolean()]
  @type result :: {:ok, binary()} | {:error, :decryption_failed}

  @namespaces [
    {~c"xenc", :"http://www.w3.org/2001/04/xmlenc#"},
    {~c"xenc11", :"http://www.w3.org/2009/xmlenc11#"},
    {~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}
  ]

  # Block ciphers of an EncryptedData: mode, :crypto cipher and key size in
  # bytes.
  @block_ciphers %{
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => {:cbc, :aes_128_cbc, 16},
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => {:cbc, :aes_192_cbc, 24},
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => {:cbc, :aes_256_cbc, 32},
    "http://www.w3.org/2009/xmlenc11#aes128-gcm" => {:gcm, :aes_128_gcm, 16},
    "http://www.w3.org/2009/xmlenc11#aes192-gcm" => {:gcm, :aes_192_gcm, 24},
    "http://www.w3.org/2009/xmlenc11#aes256-gcm" => {:gcm, :aes_256_gcm, 32}
  }

  # Key transports of an EncryptedKey.
  @rsa_oaep_mgf1p "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
  @rsa_oaep "http://www.w3.org/2009/xmlenc11#rsa-oaep"
  @rsa_1_5 "http://www.w3.org/2001/04/xmlenc#rsa-1_5"

  # The OAEP digest (ds:DigestMethod) and mask generation function
  # (xenc11:MGF) URIs; both default to SHA-1.
  @oaep_digests %{
    "http://www.w3.org/2000/09/xmldsig#sha1" => :sha,
    "http://www.w3.org/2001/04/xmlenc#sha256" => :sha256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384" => :sha384,
    "http://www.w3.org/2001/04/xmlenc#sha512" => :sha512
  }

  @oaep_mgf1_digests %{
    "http://www.w3.org/2009/xmlenc11#mgf1sha1" => :sha,
    "http://www.w3.org/2009/xmlenc11#mgf1sha224" => :sha224,
    "http://www.w3.org/2009/xmlenc11#mgf1sha256" => :sha256,
    "http://www.w3.org/2009/xmlenc11#mgf1sha384" => :sha384,
    "http://www.w3.org/2009/xmlenc11#mgf1sha512" => :sha512
  }

  @doc """
  Decrypts an `xenc:EncryptedData` element with the RSA private key its
  `ds:KeyInfo/xenc:EncryptedKey` is encrypted for, and returns the plaintext.
  """
  @spec decrypt(element(), :public_key.rsa_private_key(), opts()) :: result()
  def decrypt(encrypted_data, private_key, opts \\ []) do
    safely(fn ->
      [encrypted_key] = xpath(~c"./ds:KeyInfo/xenc:EncryptedKey", encrypted_data)
      {:ok, symmetric_key} = decrypt_key(encrypted_key, private_key, opts)
      algorithm = algorithm(encrypted_data, ~c"./xenc:EncryptionMethod")

      {:ok, plaintext} =
        decrypt_block(algorithm, symmetric_key, cipher_value(encrypted_data))

      plaintext
    end)
  end

  @doc """
  Decrypts an `xenc:EncryptedKey` element with an RSA private key, according
  to its `xenc:EncryptionMethod`, and returns the symmetric key.
  """
  @spec decrypt_key(element(), :public_key.rsa_private_key(), opts()) :: result()
  def decrypt_key(encrypted_key, private_key, opts \\ []) do
    safely(fn ->
      [encryption_method] = xpath(~c"./xenc:EncryptionMethod", encrypted_key)
      transport_opts = key_transport_opts(encryption_method, opts)
      :public_key.decrypt_private(cipher_value(encrypted_key), private_key, transport_opts)
    end)
  end

  @doc """
  Decrypts the `CipherValue` of an `EncryptedData`, already base64-decoded,
  with the block cipher whose URI is given: for CBC, the IV then the
  ciphertext of the padded plaintext; for GCM, the IV, the ciphertext, then
  the tag.
  """
  @spec decrypt_block(String.t(), binary(), binary()) :: result()
  def decrypt_block(algorithm, symmetric_key, cipher_value) do
    safely(fn ->
      {mode, cipher, key_size} = Map.fetch!(@block_ciphers, algorithm)
      ^key_size = byte_size(symmetric_key)
      block_decrypt(mode, cipher, symmetric_key, cipher_value)
    end)
  end

  defp safely(fun) do
    {:ok, fun.()}
  rescue
    _ -> {:error, :decryption_failed}
  catch
    _, _ -> {:error, :decryption_failed}
  end

  # The :public_key options of an EncryptedKey's EncryptionMethod.
  defp key_transport_opts(encryption_method, opts) do
    case algorithm(encryption_method, ~c".") do
      @rsa_oaep_mgf1p ->
        oaep_opts(encryption_method, :sha)

      @rsa_oaep ->
        mgf1_digest =
          encryption_method
          |> optional_algorithm(~c"./xenc11:MGF")
          |> lookup_algorithm(@oaep_mgf1_digests, :sha)

        oaep_opts(encryption_method, mgf1_digest)

      @rsa_1_5 ->
        if Keyword.get(opts, :allow_rsa_1_5_key_transport, false) do
          [rsa_padding: :rsa_pkcs1_padding]
        else
          Logger.warning(
            "[ExSaml.Core] RSA-1_5 key transport rejected: it is open to Bleichenbacher's " <>
              "attack. The IdP must encrypt with RSA-OAEP, or the SP be configured with " <>
              "allow_rsa_1_5_key_transport: true."
          )

          raise ArgumentError, "RSA-1_5 key transport not allowed"
        end
    end
  end

  defp oaep_opts(encryption_method, mgf1_digest) do
    digest =
      encryption_method
      |> optional_algorithm(~c"./ds:DigestMethod")
      |> lookup_algorithm(@oaep_digests, :sha)

    label =
      case xpath(~c"./xenc:OAEPparams/text()", encryption_method) do
        [text] -> :base64.decode(xmlText(text, :value))
        [] -> <<>>
      end

    [
      rsa_padding: :rsa_pkcs1_oaep_padding,
      rsa_oaep_md: digest,
      rsa_mgf1_md: mgf1_digest,
      rsa_oaep_label: label
    ]
  end

  # An unknown algorithm raises, which fails the decryption.
  defp lookup_algorithm(nil, _algorithms, default), do: default
  defp lookup_algorithm(uri, algorithms, _default), do: Map.fetch!(algorithms, uri)

  # GCM: a 12-byte IV, the ciphertext, then a 16-byte tag.
  defp block_decrypt(:gcm, cipher, symmetric_key, cipher_value) do
    encrypted_size = byte_size(cipher_value) - 12 - 16

    <<iv::binary-12, encrypted::binary-size(encrypted_size), tag::binary-16>> = cipher_value

    case :crypto.crypto_one_time_aead(cipher, symmetric_key, iv, encrypted, <<>>, tag, false) do
      plaintext when is_binary(plaintext) -> plaintext
      :error -> raise ArgumentError, "AES-GCM authentication failed"
    end
  end

  # CBC: a 16-byte IV, then the ciphertext of the padded plaintext, a whole
  # number of blocks (XML Encryption 1.1 §5.2). :crypto would silently drop a
  # trailing partial block instead of failing.
  defp block_decrypt(:cbc, cipher, symmetric_key, cipher_value) do
    <<iv::binary-16, encrypted::binary>> = cipher_value

    if encrypted == <<>> or rem(byte_size(encrypted), 16) != 0,
      do: raise(ArgumentError, "AES-CBC ciphertext is not a whole number of blocks")

    cipher
    |> :crypto.crypto_one_time(symmetric_key, iv, encrypted, false)
    |> unpad()
  end

  # XML Encryption padding (XML Encryption 1.1 §5.4.1): the last byte is the
  # padding length, from 1 to the 16-byte block size, and the padding bytes
  # before it are arbitrary.
  defp unpad(padded) do
    pad_len = :binary.last(padded)

    if pad_len in 1..16 and pad_len <= byte_size(padded),
      do: binary_part(padded, 0, byte_size(padded) - pad_len),
      else: raise(ArgumentError, "bad XML Encryption padding")
  end

  defp cipher_value(element) do
    [text] = xpath(~c"./xenc:CipherData/xenc:CipherValue/text()", element)
    :base64.decode(xmlText(text, :value))
  end

  # The Algorithm attribute of the element at `path`.
  defp algorithm(element, path) do
    [attr] = xpath(path ++ ~c"/@Algorithm", element)
    to_string(xmlAttribute(attr, :value))
  end

  # The Algorithm attribute of the element at `path`, nil when it is absent.
  defp optional_algorithm(element, path) do
    case xpath(path ++ ~c"/@Algorithm", element) do
      [attr] -> to_string(xmlAttribute(attr, :value))
      [] -> nil
    end
  end

  defp xpath(path, element), do: :xmerl_xpath.string(path, element, namespace: @namespaces)
end
