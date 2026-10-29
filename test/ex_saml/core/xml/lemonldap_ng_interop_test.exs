defmodule ExSaml.Core.Xml.LemonldapNgInteropTest do
  @moduledoc """
  A Response issued by LemonLDAP::NG 2.20.2 (IdP-initiated SSO, demo user
  `dwho`, `samlServiceSignatureMethod RSA_SHA256`, SSO message signed), with
  the IdP metadata it published. Its `ds:KeyInfo` carries the bare RSA key,
  no certificate: the signatures verify with the metadata certificate.
  """

  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.{Dsig, SafeXml}
  alias ExSaml.IdpData

  @fixtures "test/fixtures/lemonldap_ng"
  @ns [
    {~c"samlp", :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", :"urn:oasis:names:tc:SAML:2.0:assertion"},
    {~c"ds", :"http://www.w3.org/2000/09/xmldsig#"}
  ]

  setup_all do
    {:ok, metadata} = SafeXml.scan(File.read!(Path.join(@fixtures, "idp_metadata.xml")))
    certs = metadata |> IdpData.get_signing_certs() |> Enum.map(&Base.decode64!/1)
    fingerprints = Enum.map(certs, &{:sha256, :crypto.hash(:sha256, &1)})
    {:ok, response} = SafeXml.scan(File.read!(Path.join(@fixtures, "response.xml")))

    [assertion] =
      :xmerl_xpath.string(~c"/samlp:Response/saml:Assertion", response, namespace: @ns)

    %{certs: certs, fingerprints: fingerprints, response: response, assertion: assertion}
  end

  test "the Signature carries a KeyValue and no certificate", %{response: response} do
    assert [] = :xmerl_xpath.string(~c"//ds:X509Certificate", response, namespace: @ns)
    assert [_, _] = :xmerl_xpath.string(~c"//ds:KeyInfo/ds:KeyValue", response, namespace: @ns)
  end

  test "the Response and the Assertion signatures verify with the metadata certificate", ctx do
    assert :ok = Dsig.verify(ctx.response, ctx.fingerprints, trusted_certs: ctx.certs)
    assert :ok = Dsig.verify(ctx.assertion, ctx.fingerprints, trusted_certs: ctx.certs)
  end

  test "without the metadata certificate they are :missing_certificate", ctx do
    assert {:error, :missing_certificate} = Dsig.verify(ctx.response, ctx.fingerprints)
    assert {:error, :missing_certificate} = Dsig.verify(ctx.assertion, ctx.fingerprints)
  end

  test "another certificate does not verify them", ctx do
    %{cert: other} = :public_key.pkix_test_root_cert(~c"Other IdP", key: {:rsa, 2048, 65_537})
    assert {:error, :bad_signature} = Dsig.verify(ctx.response, :any, trusted_certs: [other])
  end
end
