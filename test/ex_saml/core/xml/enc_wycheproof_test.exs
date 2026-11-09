defmodule ExSaml.Core.Xml.EncWycheproofTest do
  @moduledoc """
  Wycheproof test vectors (AES-GCM, AES-CBC, RSA-OAEP) run through the XML
  Encryption decryption: the block ciphers through `Enc.decrypt_block/3`, the
  RSA-OAEP key transports through `Enc.decrypt_key/3` on an `EncryptedKey`
  built from each vector. Files and provenance: test/data/xmlenc/README.md.
  """

  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.Enc

  @dir "test/data/xmlenc/wycheproof"

  @xenc "http://www.w3.org/2001/04/xmlenc#"
  @xenc11 "http://www.w3.org/2009/xmlenc11#"

  @oaep_files [
    "rsa_oaep_2048_sha1_mgf1sha1.json",
    "rsa_oaep_2048_sha256_mgf1sha1.json",
    "rsa_oaep_2048_sha256_mgf1sha256.json",
    "rsa_oaep_2048_sha512_mgf1sha512.json"
  ]

  for file <- ["aes_gcm.json", "aes_cbc_pkcs5.json" | @oaep_files] do
    @external_resource Path.join(@dir, file)
  end

  vectors = fn file ->
    @dir |> Path.join(file) |> File.read!() |> Jason.decode!() |> Map.fetch!("testGroups")
  end

  hex = &Base.decode16!(&1, case: :lower)

  # rsa-oaep-mgf1p always uses MGF1 with SHA-1; rsa-oaep names its MGF.
  oaep_transports = fn
    "SHA-1" -> ["rsa-oaep-mgf1p", "rsa-oaep"]
    _mgf_sha -> ["rsa-oaep"]
  end

  describe "AES-GCM" do
    # XML Encryption 1.1 §5.2.4: a 96-bit IV, then the ciphertext, then a
    # 128-bit tag, and no additional authenticated data. Only those vectors
    # are kept.
    for group <- vectors.("aes_gcm.json"), tc <- group["tests"] do
      @tag wycheproof: tc["tcId"]
      test "tcId #{tc["tcId"]} (#{group["keySize"]} bits, #{tc["result"]}) #{tc["comment"]}" do
        algorithm = "#{@xenc11}aes#{unquote(group["keySize"])}-gcm"
        cipher_value = unquote(hex.(tc["iv"]) <> hex.(tc["ct"]) <> hex.(tc["tag"]))
        result = Enc.decrypt_block(algorithm, unquote(hex.(tc["key"])), cipher_value)

        case unquote(tc["result"]) do
          "valid" -> assert result == {:ok, unquote(hex.(tc["msg"]))}
          "invalid" -> assert result == {:error, :decryption_failed}
        end
      end
    end
  end

  describe "AES-CBC" do
    # Wycheproof's vectors use PKCS#7 padding. XML Encryption only reads the
    # last byte of the padding (XML Encryption 1.1 §5.4.1), so every valid
    # vector decrypts to its message, but a vector invalid for PKCS#7 because
    # of the other padding bytes is valid here; it then decrypts to the
    # plaintext without the number of bytes the last byte gives.
    for group <- vectors.("aes_cbc_pkcs5.json"), tc <- group["tests"] do
      @tag wycheproof: tc["tcId"]
      test "tcId #{tc["tcId"]} (#{group["keySize"]} bits, #{tc["result"]}) #{tc["comment"]}" do
        algorithm = "#{@xenc}aes#{unquote(group["keySize"])}-cbc"
        key = unquote(hex.(tc["key"]))
        iv = unquote(hex.(tc["iv"]))
        ct = unquote(hex.(tc["ct"]))
        result = Enc.decrypt_block(algorithm, key, iv <> ct)

        case unquote(tc["result"]) do
          "valid" -> assert result == {:ok, unquote(hex.(tc["msg"]))}
          "invalid" -> assert result == xmlenc_cbc(unquote(group["keySize"]), key, iv, ct)
        end
      end
    end
  end

  describe "RSA-OAEP key transport" do
    for file <- @oaep_files,
        group <- vectors.(file),
        transport <- oaep_transports.(group["mgfSha"]),
        tc <- group["tests"] do
      @tag wycheproof: tc["tcId"]
      test "#{file} tcId #{tc["tcId"]} as #{transport} (#{tc["result"]}) #{tc["comment"]}" do
        encrypted_key =
          encrypted_key(
            unquote(transport),
            unquote(group["sha"]),
            unquote(group["mgfSha"]),
            unquote(hex.(tc["label"])),
            unquote(hex.(tc["ct"]))
          )

        [entry] = :public_key.pem_decode(unquote(group["privateKeyPem"]))
        result = Enc.decrypt_key(encrypted_key, :public_key.pem_entry_decode(entry))

        case unquote(tc["result"]) do
          "valid" -> assert result == {:ok, unquote(hex.(tc["msg"]))}
          "invalid" -> assert result == {:error, :decryption_failed}
        end
      end
    end
  end

  # The expected XML Encryption result for a CBC vector Wycheproof marks
  # invalid for PKCS#7.
  defp xmlenc_cbc(key_size, key, iv, ct) do
    cipher = :"aes_#{key_size}_cbc"

    with true <- ct != <<>> and rem(byte_size(ct), 16) == 0,
         padded = :crypto.crypto_one_time(cipher, key, iv, ct, false),
         pad_len when pad_len in 1..16 <- :binary.last(padded) do
      {:ok, binary_part(padded, 0, byte_size(padded) - pad_len)}
    else
      _ -> {:error, :decryption_failed}
    end
  end

  # An EncryptedKey for a Wycheproof RSA-OAEP vector. The SHA-1 digest of
  # rsa-oaep-mgf1p is left implicit, to test the default.
  defp encrypted_key(transport, sha, mgf_sha, label, ct) do
    digest_method =
      if transport == "rsa-oaep-mgf1p" and sha == "SHA-1",
        do: "",
        else: ~s(<ds:DigestMethod Algorithm="#{digest_uri(sha)}"/>)

    mgf =
      if transport == "rsa-oaep",
        do: ~s(<xenc11:MGF Algorithm="#{@xenc11}mgf1#{mgf_name(mgf_sha)}"/>),
        else: ""

    oaep_params =
      if label == <<>>, do: "", else: "<xenc:OAEPparams>#{Base.encode64(label)}</xenc:OAEPparams>"

    algorithm =
      if transport == "rsa-oaep", do: "#{@xenc11}rsa-oaep", else: "#{@xenc}rsa-oaep-mgf1p"

    xml =
      ~s(<xenc:EncryptedKey xmlns:xenc="#{@xenc}" xmlns:xenc11="#{@xenc11}" ) <>
        ~s(xmlns:ds="http://www.w3.org/2000/09/xmldsig#">) <>
        ~s(<xenc:EncryptionMethod Algorithm="#{algorithm}">) <>
        digest_method <>
        mgf <>
        oaep_params <>
        ~s(</xenc:EncryptionMethod>) <>
        ~s(<xenc:CipherData><xenc:CipherValue>#{Base.encode64(ct)}</xenc:CipherValue>) <>
        ~s(</xenc:CipherData></xenc:EncryptedKey>)

    {doc, _} = xml |> String.to_charlist() |> :xmerl_scan.string(namespace_conformant: true)
    doc
  end

  defp digest_uri("SHA-1"), do: "http://www.w3.org/2000/09/xmldsig#sha1"
  defp digest_uri("SHA-256"), do: "#{@xenc}sha256"
  defp digest_uri("SHA-384"), do: "http://www.w3.org/2001/04/xmldsig-more#sha384"
  defp digest_uri("SHA-512"), do: "#{@xenc}sha512"

  defp mgf_name("SHA-" <> bits), do: "sha#{bits}"
end
