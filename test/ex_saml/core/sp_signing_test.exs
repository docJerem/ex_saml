defmodule ExSaml.Core.SpSigningTest do
  # The SP's own signatures, with each kind of key and with `sig_method`.
  use ExUnit.Case, async: true

  alias ExSaml.Core.{Sp, SpConfig}
  alias ExSaml.Core.Xml.Dsig

  require Record

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  @keys_dir Path.expand("../../data/keys", __DIR__)
  @ds_ns [{~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}]
  @idp_url "https://idp.example.com/sso"

  defp sp(key, cert, sig_method \\ nil) do
    %SpConfig{
      key: key,
      certificate: cert,
      sig_method: sig_method,
      sp_sign_requests: true,
      sp_sign_metadata: true,
      metadata_uri: "https://sp.example.com/metadata",
      consume_uri: "https://sp.example.com/consume"
    }
  end

  defp test_key(key_opt) do
    %{cert: cert, key: key} = :public_key.pkix_test_root_cert(~c"ExSaml SP", key: key_opt)
    {key, cert}
  end

  defp method_uri(xml) do
    [attr] =
      :xmerl_xpath.string(
        ~c"ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm",
        xml,
        namespace: @ds_ns
      )

    to_string(xmlAttribute(attr, :value))
  end

  # Every document the SP signs verifies, and names the expected method.
  defp assert_signs_with(sp, uri) do
    for xml <- [
          Sp.generate_authn_request(@idp_url, sp, nil),
          Sp.generate_logout_request(@idp_url, "user@example.com", sp),
          Sp.generate_logout_response(@idp_url, :success, sp),
          Sp.generate_metadata(sp)
        ] do
      assert method_uri(xml) == uri
      assert :ok = Dsig.verify(xml, [{:sha256, :crypto.hash(:sha256, sp.certificate)}])
    end
  end

  test "an RSA key signs rsa-sha256" do
    {key, cert} = test_key({:rsa, 2048, 65_537})

    assert_signs_with(sp(key, cert), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
  end

  test "an EC key signs ecdsa with the hash of its curve" do
    {key, cert} = test_key({:namedCurve, :secp256r1})
    assert_signs_with(sp(key, cert), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")

    {key, cert} = test_key({:namedCurve, :secp384r1})
    assert_signs_with(sp(key, cert), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384")
  end

  test "sig_method picks another method of the key's type" do
    {key, cert} = test_key({:namedCurve, :secp256r1})

    assert_signs_with(
      sp(key, cert, :ecdsa_sha384),
      "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    )
  end

  @tag :ml_dsa
  test "an ML-DSA key signs ml-dsa of its parameter set" do
    [entry] = @keys_dir |> Path.join("ml_dsa_65.pem") |> File.read!() |> :public_key.pem_decode()

    [{:Certificate, cert, _}] =
      @keys_dir |> Path.join("ml_dsa_65.crt") |> File.read!() |> :public_key.pem_decode()

    key = :public_key.pem_entry_decode(entry)

    assert_signs_with(sp(key, cert), "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65")
  end
end
