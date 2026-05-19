defmodule ExSaml.Core.Xml.SafeXmlTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.SafeXml

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  describe "scan/1" do
    test "parses a well-formed XML binary" do
      assert {:ok, root} = SafeXml.scan("<root><child>hello</child></root>")
      assert Record.is_record(root, :xmlElement)
      assert xmlElement(root, :name) == :root
    end

    test "parses a charlist input identically to a binary input" do
      xml = "<root/>"
      assert {:ok, from_binary} = SafeXml.scan(xml)
      assert {:ok, from_charlist} = SafeXml.scan(String.to_charlist(xml))
      assert xmlElement(from_binary, :name) == xmlElement(from_charlist, :name)
    end

    test "accepts UTF-8 multibyte content in element values" do
      assert {:ok, _root} = SafeXml.scan("<root>éàü — ✓</root>")
    end

    test "returns {:error, :invalid_xml} on malformed input" do
      assert {:error, :invalid_xml} = SafeXml.scan("<not-closed>")
    end

    test "returns {:error, :invalid_xml} on empty input" do
      assert {:error, :invalid_xml} = SafeXml.scan("")
    end

    test "rejects DOCTYPE with an external entity (XXE)" do
      xxe = """
      <?xml version="1.0"?>
      <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <foo>&xxe;</foo>
      """

      assert {:error, :invalid_xml} = SafeXml.scan(xxe)
    end

    test "rejects DOCTYPE with an internal entity expansion" do
      doc = """
      <?xml version="1.0"?>
      <!DOCTYPE foo [
        <!ENTITY hello "world">
      ]>
      <foo>&hello;</foo>
      """

      assert {:error, :invalid_xml} = SafeXml.scan(doc)
    end
  end

  describe "scan!/1" do
    test "returns the root element on success" do
      root = SafeXml.scan!("<root/>")
      assert Record.is_record(root, :xmlElement)
      assert xmlElement(root, :name) == :root
    end

    test "raises ArgumentError on malformed input" do
      assert_raise ArgumentError, ~r/invalid XML/, fn ->
        SafeXml.scan!("<broken")
      end
    end

    test "raises ArgumentError on XXE input" do
      xxe = """
      <?xml version="1.0"?>
      <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <foo>&xxe;</foo>
      """

      assert_raise ArgumentError, ~r/invalid XML/, fn ->
        SafeXml.scan!(xxe)
      end
    end
  end
end
