defmodule ExSaml.Core.Xml.EncW3cTest do
  @moduledoc """
  Decryption of the XML Encryption 1.1 test cases of the W3C XML Security
  Working Group, with the key transported in RSA-OAEP (WRAP.1 to WRAP.4,
  contributed by Oracle). Files and provenance: test/data/xmlenc/README.md.
  """

  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.{C14n, Enc}

  @dir "test/data/xmlenc/w3c"

  # {test case, ciphertext file, private key}
  @cases [
    {"WRAP.1 aes128-gcm, rsa-oaep-mgf1p", "cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml",
     "RSA-2048"},
    {"WRAP.2 aes192-gcm, rsa-oaep-mgf1p with a SHA-256 DigestMethod",
     "cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml", "RSA-3072"},
    {"WRAP.3 aes256-gcm, rsa-oaep with SHA-384 and MGF1 SHA-1",
     "cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml", "RSA-3072"},
    {"WRAP.4 aes256-gcm, rsa-oaep with SHA-512, MGF1 SHA-1 and OAEPparams",
     "cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml", "RSA-4096"}
  ]

  for file <- ["plaintext.xml" | Enum.map(@cases, &elem(&1, 1))] do
    @external_resource Path.join(@dir, file)
  end

  describe "Enc.decrypt/3 decrypts" do
    for {name, file, key} <- @cases do
      test name do
        assert {:ok, plaintext} =
                 Enc.decrypt(encrypted_data(unquote(file)), private_key(unquote(key)))

        # The encrypter serialized the empty <Expires/> as <Expires></Expires>:
        # the documents are compared in canonical form.
        assert canonical(plaintext) == canonical(File.read!(Path.join(@dir, "plaintext.xml")))
      end
    end
  end

  describe "Enc.decrypt/3 rejects" do
    test "WRAP.1 with another private key" do
      assert {:error, :decryption_failed} =
               Enc.decrypt(
                 encrypted_data("cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml"),
                 private_key("RSA-3072")
               )
    end

    test "WRAP.2 without its SHA-256 DigestMethod" do
      xml =
        "cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml"
        |> read()
        |> String.replace(
          "http://www.w3.org/2001/04/xmlenc#sha256",
          "http://www.w3.org/2000/09/xmldsig#sha1"
        )

      assert {:error, :decryption_failed} = Enc.decrypt(parse(xml), private_key("RSA-3072"))
    end

    test "WRAP.3 with another MGF" do
      xml =
        "cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml"
        |> read()
        |> String.replace("xmlenc11#mgf1sha1", "xmlenc11#mgf1sha256")

      assert {:error, :decryption_failed} = Enc.decrypt(parse(xml), private_key("RSA-3072"))
    end

    test "WRAP.4 with other OAEPparams" do
      xml =
        "cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml"
        |> read()
        |> String.replace(Base.encode64("dummy123"), Base.encode64("dummy124"))

      assert {:error, :decryption_failed} = Enc.decrypt(parse(xml), private_key("RSA-4096"))
    end

    test "WRAP.1 with an altered ciphertext" do
      file = "cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml"

      [_, data_b64] =
        Regex.run(
          ~r{</xenc:EncryptedKey></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>([^<]+)},
          read(file)
        )

      <<first, rest::binary>> = Base.decode64!(data_b64, ignore: :whitespace)
      altered = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)

      xml = String.replace(read(file), data_b64, altered)

      assert {:error, :decryption_failed} = Enc.decrypt(parse(xml), private_key("RSA-2048"))
    end
  end

  defp read(file), do: File.read!(Path.join(@dir, file))

  defp encrypted_data(file), do: file |> read() |> parse()

  defp parse(xml) do
    {doc, _} =
      xml
      |> String.to_charlist()
      |> :xmerl_scan.string(namespace_conformant: true, allow_entities: false)

    doc
  end

  defp canonical(xml), do: xml |> parse() |> C14n.c14n(false)

  defp private_key(name) do
    [entry] = :public_key.pem_decode(read("#{name}_SHA256WithRSA.key.pem"))
    :public_key.pem_entry_decode(entry)
  end
end
