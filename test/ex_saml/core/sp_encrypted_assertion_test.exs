defmodule ExSaml.Core.SpEncryptedAssertionTest do
  # Encrypted assertions (XML Encryption 1.0 and 1.1), encrypted by an
  # encrypter independent of ExSaml, built on :crypto and :public_key only,
  # then decrypted by Sp.validate_assertion/2 with the SP's private key.
  use ExUnit.Case, async: true

  alias ExSaml.Core.{Assertion, Contact, Org, Sp, SpConfig, Subject}

  @consume_uri "https://sp.example.com/consume"
  @metadata_uri "https://sp.example.com/metadata"

  # EncryptionMethod of the EncryptedData: URI, :crypto cipher, key bytes.
  @block_ciphers %{
    aes128_cbc: {"http://www.w3.org/2001/04/xmlenc#aes128-cbc", :aes_128_cbc, 16},
    aes256_cbc: {"http://www.w3.org/2001/04/xmlenc#aes256-cbc", :aes_256_cbc, 32},
    aes128_gcm: {"http://www.w3.org/2009/xmlenc11#aes128-gcm", :aes_128_gcm, 16},
    aes256_gcm: {"http://www.w3.org/2009/xmlenc11#aes256-gcm", :aes_256_gcm, 32}
  }

  # EncryptionMethod of the EncryptedKey: URI and RSA padding.
  @key_transports %{
    rsa_oaep_mgf1p: {"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", :rsa_pkcs1_oaep_padding},
    rsa_1_5: {"http://www.w3.org/2001/04/xmlenc#rsa-1_5", :rsa_pkcs1_padding}
  }

  setup_all do
    {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
      key = :public_key.generate_key({:rsa, 2048, 65_537})

    %{sp_key: key, sp_public_key: {:RSAPublicKey, n, e}}
  end

  defp sp(key) do
    %SpConfig{
      metadata_uri: @metadata_uri,
      consume_uri: @consume_uri,
      key: key,
      idp_signs_assertions: false,
      idp_signs_envelopes: false,
      org: %Org{name: "Test Org", displayname: "Test Org", url: "https://example.com"},
      tech: %Contact{name: "Admin", email: "admin@example.com"}
    }
  end

  defp saml_time(offset_secs) do
    DateTime.utc_now()
    |> DateTime.add(offset_secs)
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end

  defp assertion_xml do
    ~s|<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" | <>
      ~s|ID="_a1" Version="2.0" IssueInstant="#{saml_time(0)}">| <>
      ~s|<saml:Issuer>https://idp.example.com</saml:Issuer>| <>
      ~s|<saml:Subject><saml:NameID>alice@example.com</saml:NameID>| <>
      ~s|<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">| <>
      ~s|<saml:SubjectConfirmationData Recipient="#{@consume_uri}" | <>
      ~s|NotOnOrAfter="#{saml_time(300)}"/></saml:SubjectConfirmation></saml:Subject>| <>
      ~s|<saml:Conditions NotBefore="#{saml_time(-60)}" NotOnOrAfter="#{saml_time(300)}">| <>
      ~s|<saml:AudienceRestriction><saml:Audience>#{@metadata_uri}</saml:Audience>| <>
      ~s|</saml:AudienceRestriction></saml:Conditions>| <>
      ~s|<saml:AuthnStatement AuthnInstant="#{saml_time(0)}" SessionIndex="_s1"/>| <>
      ~s|</saml:Assertion>|
  end

  # XML Encryption padding (§5.2): any bytes, then the padding length.
  defp pad(plaintext, filler) do
    pad_len = 16 - rem(byte_size(plaintext), 16)
    plaintext <> :binary.copy(<<filler>>, pad_len - 1) <> <<pad_len>>
  end

  defp encrypt_block(plaintext, cipher, key, opts) when cipher in [:aes_128_gcm, :aes_256_gcm] do
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(cipher, key, iv, plaintext, <<>>, true)
    tag = if opts[:tamper_tag], do: :crypto.exor(tag, <<1::128>>), else: tag
    iv <> ciphertext <> tag
  end

  defp encrypt_block(plaintext, cipher, key, opts) do
    iv = :crypto.strong_rand_bytes(16)
    padded = pad(plaintext, Keyword.get(opts, :padding_filler, 0xAA))
    iv <> :crypto.crypto_one_time(cipher, key, iv, padded, true)
  end

  # A Response carrying the assertion encrypted for `recipient_public_key`.
  defp encrypted_response(recipient_public_key, block, transport, opts \\ []) do
    {block_uri, cipher, key_size} = Map.fetch!(@block_ciphers, block)
    {transport_uri, padding} = Map.fetch!(@key_transports, transport)

    symmetric_key = :crypto.strong_rand_bytes(key_size)
    cipher_value = encrypt_block(assertion_xml(), cipher, symmetric_key, opts)

    encrypted_key =
      :public_key.encrypt_public(symmetric_key, recipient_public_key, rsa_padding: padding)

    ~s|<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" | <>
      ~s|xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" | <>
      ~s|ID="_r1" Version="2.0" IssueInstant="#{saml_time(0)}" Destination="#{@consume_uri}">| <>
      ~s|<saml:Issuer>https://idp.example.com</saml:Issuer>| <>
      ~s|<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>| <>
      ~s|</samlp:Status><saml:EncryptedAssertion>| <>
      ~s|<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" | <>
      ~s|Type="http://www.w3.org/2001/04/xmlenc#Element">| <>
      ~s|<xenc:EncryptionMethod Algorithm="#{block_uri}"/>| <>
      ~s|<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>| <>
      ~s|<xenc:EncryptionMethod Algorithm="#{transport_uri}"/>| <>
      ~s|<xenc:CipherData><xenc:CipherValue>#{Base.encode64(encrypted_key)}</xenc:CipherValue>| <>
      ~s|</xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>| <>
      ~s|<xenc:CipherData><xenc:CipherValue>#{Base.encode64(cipher_value)}</xenc:CipherValue>| <>
      ~s|</xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>|
  end

  defp parse(xml) do
    {doc, []} =
      xml
      |> String.to_charlist()
      |> :xmerl_scan.string(namespace_conformant: true, allow_entities: false)

    doc
  end

  describe "Sp.validate_assertion/2 decrypts" do
    for block <- [:aes128_cbc, :aes256_cbc, :aes128_gcm],
        transport <- [:rsa_oaep_mgf1p, :rsa_1_5] do
      test "#{block} with a #{transport} key", %{sp_key: key, sp_public_key: public_key} do
        xml = encrypted_response(public_key, unquote(block), unquote(transport))

        assert {:ok, %Assertion{subject: %Subject{name: "alice@example.com"}} = assertion} =
                 Sp.validate_assertion(parse(xml), sp(key))

        assert assertion.recipient == @consume_uri
      end
    end

    # The padding bytes before the length are arbitrary: PKCS#7 fills them
    # with the length, others with random bytes.
    for filler <- [0x00, 0x10, 0xFF] do
      test "aes128_cbc whatever the padding bytes (#{filler})", %{
        sp_key: key,
        sp_public_key: public_key
      } do
        xml =
          encrypted_response(public_key, :aes128_cbc, :rsa_oaep_mgf1p,
            padding_filler: unquote(filler)
          )

        assert {:ok, %Assertion{}} = Sp.validate_assertion(parse(xml), sp(key))
      end
    end
  end

  describe "Sp.validate_assertion/2 rejects with :bad_assertion" do
    test "an assertion encrypted for another key", %{sp_key: key} do
      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
        :public_key.generate_key({:rsa, 2048, 65_537})

      xml = encrypted_response({:RSAPublicKey, n, e}, :aes128_gcm, :rsa_oaep_mgf1p)

      assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
    end

    test "an AES-GCM ciphertext whose tag was altered", %{sp_key: key, sp_public_key: public_key} do
      xml = encrypted_response(public_key, :aes128_gcm, :rsa_oaep_mgf1p, tamper_tag: true)

      assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
    end

    test "an unsupported block cipher (aes256-gcm)", %{sp_key: key, sp_public_key: public_key} do
      xml = encrypted_response(public_key, :aes256_gcm, :rsa_oaep_mgf1p)

      assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
    end
  end
end
