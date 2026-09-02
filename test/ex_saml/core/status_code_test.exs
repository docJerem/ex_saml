defmodule ExSaml.Core.StatusCodeTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.StatusCode

  @prefix "urn:oasis:names:tc:SAML:2.0:status:"

  @spec_uris ~w(Success Requester Responder VersionMismatch AuthnFailed InvalidAttrNameOrValue
    InvalidNameIDPolicy NoAuthnContext NoAvailableIDP NoPassive NoSupportedIDP PartialLogout
    ProxyCountExceeded RequestDenied RequestUnsupported RequestVersionDeprecated
    RequestVersionTooHigh RequestVersionTooLow ResourceNotRecognized TooManyResponses
    UnknownAttrProfile UnknownPrincipal UnsupportedBinding)

  test "covers the 23 status codes of SAML 2.0 Core §3.2.2.2" do
    assert length(StatusCode.all()) == 23
    assert length(@spec_uris) == 23
  end

  test "to_atom/1 <-> to_uri/1 round-trip over every spec URI, binary and charlist" do
    for suffix <- @spec_uris do
      uri = @prefix <> suffix
      atom = StatusCode.to_atom(uri)

      refute atom == :unknown, "#{uri} is not in the catalogue"
      assert StatusCode.to_uri(atom) == uri
      assert StatusCode.to_atom(String.to_charlist(uri)) == atom
    end
  end

  test "top level vs second level" do
    assert StatusCode.top_level() == [:success, :requester, :responder, :version_mismatch]
    assert length(StatusCode.second_level()) == 19

    assert StatusCode.top_level?(:responder)
    refute StatusCode.top_level?(:authn_failed)
    assert StatusCode.second_level?(:authn_failed)
    refute StatusCode.second_level?(:responder)
  end

  test "unknown URIs" do
    assert StatusCode.to_atom("urn:example:nope") == :unknown
    assert StatusCode.to_atom(~c"urn:example:nope") == :unknown
    assert StatusCode.to_atom(nil) == :unknown
    assert StatusCode.to_atom(@prefix <> "authnfailed") == :unknown

    assert_raise ArgumentError, fn -> StatusCode.to_uri(:nope) end
  end
end
