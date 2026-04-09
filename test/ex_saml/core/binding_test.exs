defmodule ExSaml.Core.BindingTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Binding

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlDocument,
    Record.extract(:xmlDocument, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp simple_request_element do
    # Build a minimal <AuthnRequest/> xmerl element
    xmlElement(
      name: :AuthnRequest,
      expanded_name: :AuthnRequest,
      nsinfo: [],
      namespace: {:xmlNamespace, [], []},
      parents: [],
      pos: 1,
      attributes: [],
      content: [],
      language: [],
      xmlbase: ~c"/",
      elementdef: :undeclared
    )
  end

  defp simple_response_element do
    xmlElement(
      name: :Response,
      expanded_name: :Response,
      nsinfo: [],
      namespace: {:xmlNamespace, [], []},
      parents: [],
      pos: 1,
      attributes: [],
      content: [],
      language: [],
      xmlbase: ~c"/",
      elementdef: :undeclared
    )
  end

  # ---------------------------------------------------------------------------
  # encode_http_post/4 + decode_response/2 roundtrip
  # ---------------------------------------------------------------------------

  describe "encode_http_post/4 and decode_response/2 roundtrip" do
    test "encodes an XML element as an HTML form and the payload can be decoded back" do
      elem = simple_request_element()
      html = Binding.encode_http_post("https://idp.example.com/sso", elem, "relay123")

      assert is_binary(html)
      assert html =~ "SAMLRequest"
      assert html =~ "relay123"
      assert html =~ "https://idp.example.com/sso"
      assert html =~ "<form"
      assert html =~ "saml-req-form"

      # Extract the base64 payload from the hidden input
      [_, b64_payload] = Regex.run(~r/name="SAMLRequest" value="([^"]+)"/, html)

      # decode_response with nil encoding (non-deflate path) should parse it
      decoded = Binding.decode_response("", b64_payload)
      assert Record.is_record(decoded, :xmlElement)
      assert xmlElement(decoded, :name) == :AuthnRequest
    end
  end

  # ---------------------------------------------------------------------------
  # encode_http_redirect/4
  # ---------------------------------------------------------------------------

  describe "encode_http_redirect/4" do
    test "encodes a SAMLRequest with proper query parameters" do
      elem = simple_request_element()

      url =
        Binding.encode_http_redirect(
          "https://idp.example.com/sso",
          elem,
          nil,
          "relay_state_value"
        )

      assert is_binary(url)
      assert url =~ "SAMLEncoding="
      assert url =~ "SAMLRequest="
      assert url =~ "RelayState="
      assert url =~ "relay_state_value"
      assert String.starts_with?(url, "https://idp.example.com/sso?")
    end

    test "uses SAMLResponse for Response elements" do
      elem = simple_response_element()

      url =
        Binding.encode_http_redirect(
          "https://idp.example.com/sso",
          elem,
          nil,
          "relay"
        )

      assert url =~ "SAMLResponse="
    end

    test "appends & when target URL already has query parameters" do
      elem = simple_request_element()

      url =
        Binding.encode_http_redirect(
          "https://idp.example.com/sso?existing=param",
          elem,
          nil,
          "relay"
        )

      assert url =~ "sso?existing=param&SAMLEncoding="
    end
  end

  # ---------------------------------------------------------------------------
  # decode_response/2
  # ---------------------------------------------------------------------------

  describe "decode_response/2" do
    test "decodes a base64+deflate SAMLResponse with DEFLATE encoding" do
      xml_str = "<AuthnRequest>test</AuthnRequest>"
      compressed = :zlib.zip(xml_str)
      b64 = Base.encode64(compressed)

      decoded =
        Binding.decode_response(
          "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE",
          b64
        )

      assert Record.is_record(decoded, :xmlElement)
      assert xmlElement(decoded, :name) == :AuthnRequest
    end

    test "decodes plain base64 SAMLResponse without deflate" do
      xml_str = "<Response>hello</Response>"
      b64 = Base.encode64(xml_str)

      decoded = Binding.decode_response("", b64)

      assert Record.is_record(decoded, :xmlElement)
      assert xmlElement(decoded, :name) == :Response
    end
  end

  # ---------------------------------------------------------------------------
  # encode_http_post/4 with nonce
  # ---------------------------------------------------------------------------

  describe "encode_http_post/4 with nonce" do
    test "generates HTML with nonce attribute on the script tag" do
      elem = simple_request_element()
      nonce = "abc123xyz"

      html =
        Binding.encode_http_post("https://idp.example.com/sso", elem, "relay", nonce)

      assert html =~ ~s(nonce="abc123xyz")
      assert html =~ "<script nonce="
    end

    test "generates HTML without nonce attribute when nonce is empty" do
      elem = simple_request_element()

      html = Binding.encode_http_post("https://idp.example.com/sso", elem, "relay", "")

      refute html =~ "nonce="
      assert html =~ "<script >\n"
    end
  end
end
