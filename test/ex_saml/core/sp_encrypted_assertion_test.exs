defmodule ExSaml.Core.SpEncryptedAssertionTest do
  # Encrypted assertions (XML Encryption 1.0 and 1.1), encrypted by an
  # encrypter independent of ExSaml, built on :crypto and :public_key only,
  # then decrypted by Sp.validate_assertion/2 with the SP's private key.
  # Not async: the `:unsigned_cbc` tests set `:enforced_response_checks`.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.Core.{Assertion, Contact, Org, Sp, SpConfig, Subject}
  alias ExSaml.Core.Xml.Dsig

  @consume_uri "https://sp.example.com/consume"
  @metadata_uri "https://sp.example.com/metadata"

  @xmldsig "http://www.w3.org/2000/09/xmldsig#"

  # EncryptionMethod of the EncryptedData: URI, :crypto cipher, key bytes.
  @block_ciphers %{
    aes128_cbc: {"http://www.w3.org/2001/04/xmlenc#aes128-cbc", :aes_128_cbc, 16},
    aes192_cbc: {"http://www.w3.org/2001/04/xmlenc#aes192-cbc", :aes_192_cbc, 24},
    aes256_cbc: {"http://www.w3.org/2001/04/xmlenc#aes256-cbc", :aes_256_cbc, 32},
    aes128_gcm: {"http://www.w3.org/2009/xmlenc11#aes128-gcm", :aes_128_gcm, 16},
    aes192_gcm: {"http://www.w3.org/2009/xmlenc11#aes192-gcm", :aes_192_gcm, 24},
    aes256_gcm: {"http://www.w3.org/2009/xmlenc11#aes256-gcm", :aes_256_gcm, 32}
  }

  # EncryptionMethod of the EncryptedKey: URI, :public_key options and the
  # child elements that state them. rsa-oaep-mgf1p always masks with
  # MGF1-SHA1, whatever its digest; :crypto defaults MGF1 to the digest.
  @key_transports %{
    rsa_oaep_mgf1p: {"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", [], ""},
    rsa_oaep_mgf1p_sha256:
      {"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
       [rsa_oaep_md: :sha256, rsa_mgf1_md: :sha],
       ~s|<ds:DigestMethod xmlns:ds="#{@xmldsig}" | <>
         ~s|Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>|},
    rsa_oaep: {"http://www.w3.org/2009/xmlenc11#rsa-oaep", [], ""},
    rsa_oaep_sha256_mgf1sha256:
      {"http://www.w3.org/2009/xmlenc11#rsa-oaep", [rsa_oaep_md: :sha256, rsa_mgf1_md: :sha256],
       ~s|<ds:DigestMethod xmlns:ds="#{@xmldsig}" | <>
         ~s|Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>| <>
         ~s|<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" | <>
         ~s|Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>|},
    rsa_oaep_label:
      {"http://www.w3.org/2009/xmlenc11#rsa-oaep", [rsa_oaep_label: "ex_saml"],
       ~s|<xenc:OAEPparams>#{Base.encode64("ex_saml")}</xenc:OAEPparams>|},
    rsa_oaep_unknown_digest:
      {"http://www.w3.org/2009/xmlenc11#rsa-oaep", [],
       ~s|<ds:DigestMethod xmlns:ds="#{@xmldsig}" | <>
         ~s|Algorithm="http://www.w3.org/2001/04/xmldsig-more#md5"/>|},
    rsa_1_5: {"http://www.w3.org/2001/04/xmlenc#rsa-1_5", [rsa_padding: :rsa_pkcs1_padding], ""}
  }

  setup_all do
    {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
      key = :public_key.generate_key({:rsa, 2048, 65_537})

    %{sp_key: key, sp_public_key: {:RSAPublicKey, n, e}}
  end

  setup do
    previous = Application.get_env(:ex_saml, :enforced_response_checks)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ex_saml, :enforced_response_checks, previous),
        else: Application.delete_env(:ex_saml, :enforced_response_checks)
    end)

    :ok
  end

  defp sp(key, overrides \\ []) do
    struct!(
      %SpConfig{
        metadata_uri: @metadata_uri,
        consume_uri: @consume_uri,
        key: key,
        idp_signs_assertions: false,
        idp_signs_envelopes: false,
        allow_unsigned: true,
        org: %Org{name: "Test Org", displayname: "Test Org", url: "https://example.com"},
        tech: %Contact{name: "Admin", email: "admin@example.com"}
      },
      overrides
    )
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

  # XML Encryption padding (§5.4.1): any bytes, then the padding length.
  defp pad(plaintext, opts) do
    pad_len = Keyword.get(opts, :pad_len, 16 - rem(byte_size(plaintext), 16))
    filler = Keyword.get(opts, :padding_filler, 0xAA)
    plaintext <> :binary.copy(<<filler>>, max(pad_len - 1, 0)) <> <<pad_len>>
  end

  defp encrypt_block(plaintext, cipher, key, opts)
       when cipher in [:aes_128_gcm, :aes_192_gcm, :aes_256_gcm] do
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(cipher, key, iv, plaintext, <<>>, true)
    tag = if opts[:tamper_tag], do: :crypto.exor(tag, <<1::128>>), else: tag
    iv <> ciphertext <> tag
  end

  defp encrypt_block(plaintext, cipher, key, opts) do
    iv = :crypto.strong_rand_bytes(16)
    iv <> :crypto.crypto_one_time(cipher, key, iv, pad(plaintext, opts), true)
  end

  defp encrypt_key(symmetric_key, public_key, {_uri, [rsa_padding: padding], _xml}),
    do: :public_key.encrypt_public(symmetric_key, public_key, rsa_padding: padding)

  defp encrypt_key(symmetric_key, public_key, {_uri, oaep_opts, _xml}) do
    opts = [rsa_padding: :rsa_pkcs1_oaep_padding] ++ oaep_opts
    :public_key.encrypt_public(symmetric_key, public_key, opts)
  end

  defp encrypted_assertion(recipient_public_key, block, transport, opts) do
    {block_uri, cipher, key_size} = Map.fetch!(@block_ciphers, block)
    {transport_uri, _oaep_opts, transport_xml} = spec = Map.fetch!(@key_transports, transport)

    symmetric_key = :crypto.strong_rand_bytes(key_size)
    cipher_value = encrypt_block(assertion_xml(), cipher, symmetric_key, opts)
    encrypted_key = encrypt_key(symmetric_key, recipient_public_key, spec)

    ~s|<saml:EncryptedAssertion>| <>
      ~s|<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" | <>
      ~s|Type="http://www.w3.org/2001/04/xmlenc#Element">| <>
      ~s|<xenc:EncryptionMethod Algorithm="#{block_uri}"/>| <>
      ~s|<ds:KeyInfo xmlns:ds="#{@xmldsig}"><xenc:EncryptedKey>| <>
      ~s|<xenc:EncryptionMethod Algorithm="#{transport_uri}">#{transport_xml}| <>
      ~s|</xenc:EncryptionMethod>| <>
      ~s|<xenc:CipherData><xenc:CipherValue>#{Base.encode64(encrypted_key)}</xenc:CipherValue>| <>
      ~s|</xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>| <>
      ~s|<xenc:CipherData><xenc:CipherValue>#{Base.encode64(cipher_value)}</xenc:CipherValue>| <>
      ~s|</xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>|
  end

  # A Response carrying the assertion encrypted for `recipient_public_key`.
  defp encrypted_response(recipient_public_key, block, transport, opts \\ []) do
    ~s|<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" | <>
      ~s|xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" | <>
      ~s|ID="_r1" Version="2.0" IssueInstant="#{saml_time(0)}" Destination="#{@consume_uri}">| <>
      ~s|<saml:Issuer>https://idp.example.com</saml:Issuer>| <>
      ~s|<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>| <>
      ~s|</samlp:Status>| <>
      encrypted_assertion(recipient_public_key, block, transport, opts) <>
      ~s|</samlp:Response>|
  end

  defp parse(xml) do
    {doc, []} =
      xml
      |> String.to_charlist()
      |> :xmerl_scan.string(namespace_conformant: true, allow_entities: false)

    doc
  end

  defp to_xml_string(element),
    do: [element] |> :xmerl.export(:xmerl_xml) |> List.flatten() |> to_string()

  describe "Sp.validate_assertion/2 decrypts" do
    for block <- [:aes128_cbc, :aes192_cbc, :aes256_cbc, :aes128_gcm, :aes192_gcm, :aes256_gcm],
        transport <- [:rsa_oaep_mgf1p, :rsa_oaep] do
      test "#{block} with a #{transport} key", %{sp_key: key, sp_public_key: public_key} do
        xml = encrypted_response(public_key, unquote(block), unquote(transport))

        assert {:ok, %Assertion{subject: %Subject{name: "alice@example.com"}} = assertion} =
                 Sp.validate_assertion(parse(xml), sp(key))

        assert assertion.recipient == @consume_uri
      end
    end

    for transport <- [:rsa_oaep_mgf1p_sha256, :rsa_oaep_sha256_mgf1sha256, :rsa_oaep_label] do
      test "a #{transport} key, with its DigestMethod, MGF or OAEPparams", %{
        sp_key: key,
        sp_public_key: public_key
      } do
        xml = encrypted_response(public_key, :aes256_gcm, unquote(transport))

        assert {:ok, %Assertion{}} = Sp.validate_assertion(parse(xml), sp(key))
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

    test "an RSA-1_5 key when the SP allows it", %{sp_key: key, sp_public_key: public_key} do
      xml = encrypted_response(public_key, :aes128_cbc, :rsa_1_5)

      assert {:ok, %Assertion{}} =
               Sp.validate_assertion(parse(xml), sp(key, allow_rsa_1_5_key_transport: true))
    end
  end

  describe "Sp.validate_assertion/2 rejects with :bad_assertion" do
    test "an RSA-1_5 key by default", %{sp_key: key, sp_public_key: public_key} do
      xml = encrypted_response(public_key, :aes128_cbc, :rsa_1_5)

      log =
        capture_log(fn ->
          assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
        end)

      assert log =~ "RSA-1_5 key transport rejected"
    end

    test "an assertion encrypted for another key", %{sp_key: key} do
      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} =
        :public_key.generate_key({:rsa, 2048, 65_537})

      xml = encrypted_response({:RSAPublicKey, n, e}, :aes128_gcm, :rsa_oaep_mgf1p)

      assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
    end

    test "an AES-GCM ciphertext whose tag was altered", %{sp_key: key, sp_public_key: public_key} do
      xml = encrypted_response(public_key, :aes256_gcm, :rsa_oaep_mgf1p, tamper_tag: true)

      assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
    end

    # The last byte must be the padding length, 1 to 16.
    for pad_len <- [0, 17, 255] do
      test "an AES-CBC padding length of #{pad_len}", %{sp_key: key, sp_public_key: public_key} do
        xml =
          encrypted_response(public_key, :aes128_cbc, :rsa_oaep_mgf1p,
            pad_len: unquote(pad_len),
            padding_filler: 0x20
          )

        assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
      end
    end

    test "an unknown OAEP DigestMethod", %{sp_key: key, sp_public_key: public_key} do
      xml = encrypted_response(public_key, :aes128_gcm, :rsa_oaep_unknown_digest)

      assert {:error, :bad_assertion} = Sp.validate_assertion(parse(xml), sp(key))
    end
  end

  # An AES-CBC assertion in a Response whose signature is not required is
  # decrypted before anything is verified: a padding oracle for anyone who can
  # post to the ACS. Log-only by default, so each such IdP can be found and
  # moved to AES-GCM, a signed Response or `allow_unsigned_cbc` first.
  describe ":unsigned_cbc" do
    test "an AES-CBC assertion in an unsigned Response is decrypted and logged by default", %{
      sp_key: key,
      sp_public_key: public_key
    } do
      xml = encrypted_response(public_key, :aes256_cbc, :rsa_oaep)

      log =
        capture_log(fn ->
          assert {:ok, %Assertion{}} = Sp.validate_assertion(parse(xml), sp(key))
        end)

      assert log =~ "[ExSaml] saml_validation check=:unsigned_cbc enforced=false"
      assert log =~ ~s(actual="http://www.w3.org/2001/04/xmlenc#aes256-cbc")
    end

    test "is rejected before decryption when the check is enforced", %{
      sp_key: key,
      sp_public_key: public_key
    } do
      Application.put_env(:ex_saml, :enforced_response_checks, :all)
      xml = encrypted_response(public_key, :aes128_cbc, :rsa_oaep_mgf1p, pad_len: 17)

      assert {:error, :unsigned_cbc} = Sp.validate_assertion(parse(xml), sp(key))
    end

    test "is decrypted when the IdP is allowed AES-CBC in an unsigned Response", %{
      sp_key: key,
      sp_public_key: public_key
    } do
      Application.put_env(:ex_saml, :enforced_response_checks, :all)
      xml = encrypted_response(public_key, :aes128_cbc, :rsa_oaep_mgf1p)

      log =
        capture_log(fn ->
          assert {:ok, %Assertion{}} =
                   Sp.validate_assertion(parse(xml), sp(key, allow_unsigned_cbc: true))
        end)

      refute log =~ "unsigned_cbc"
    end

    test "an AES-GCM assertion in an unsigned Response is not flagged", %{
      sp_key: key,
      sp_public_key: public_key
    } do
      Application.put_env(:ex_saml, :enforced_response_checks, :all)
      xml = encrypted_response(public_key, :aes128_gcm, :rsa_oaep_mgf1p)

      log =
        capture_log(fn ->
          assert {:ok, %Assertion{}} = Sp.validate_assertion(parse(xml), sp(key))
        end)

      refute log =~ "unsigned_cbc"
    end
  end

  describe "a signed envelope" do
    setup %{sp_key: key, sp_public_key: public_key} do
      %{cert: idp_cert, key: idp_key} =
        :public_key.pkix_test_root_cert(~c"Interop IdP", key: {:rsa, 2048, 65_537})

      signed_xml =
        public_key
        |> encrypted_response(:aes128_cbc, :rsa_oaep_mgf1p)
        |> parse()
        |> Dsig.sign(idp_key, idp_cert, :rsa_sha256)
        |> to_xml_string()

      sp =
        sp(key,
          idp_signs_envelopes: true,
          trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, idp_cert)}]
        )

      %{signed_xml: signed_xml, sp: sp}
    end

    test "is verified, then the assertion decrypted", %{signed_xml: xml, sp: sp} do
      Application.put_env(:ex_saml, :enforced_response_checks, :all)

      log =
        capture_log(fn ->
          assert {:ok, %Assertion{}} = Sp.validate_assertion(parse(xml), sp)
        end)

      refute log =~ "unsigned_cbc"
    end

    # An altered ciphertext fails the envelope signature, before any decryption.
    test "is verified before the assertion is decrypted", %{signed_xml: xml, sp: sp} do
      [cipher_b64] =
        ~r|<xenc:CipherData><xenc:CipherValue>([^<]+)</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>|
        |> Regex.run(xml, capture: :all_but_first)

      <<first, rest::binary>> = Base.decode64!(cipher_b64)
      tampered = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)

      assert {:error, {:envelope, {:error, :bad_digest}}} =
               xml |> String.replace(cipher_b64, tampered) |> parse() |> Sp.validate_assertion(sp)
    end
  end
end
