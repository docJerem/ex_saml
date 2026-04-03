defmodule ExSaml.Core.Xml.C14nTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Xml.C14n

  require Record
  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlAttribute, Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlNamespace, Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl"))

  defp parse(xml) do
    {doc, _} = :xmerl_scan.string(String.to_charlist(xml), namespace_conformant: true)
    doc
  end

  defp parse_doc(xml) do
    {doc, _} =
      :xmerl_scan.string(String.to_charlist(xml), namespace_conformant: true, document: true)

    doc
  end

  describe "canon_name/1" do
    test "resolves attribute namespace" do
      attr =
        xmlAttribute(
          name: :Blah,
          nsinfo: {"foo", "Blah"},
          namespace: xmlNamespace(nodes: [{"foo", :"urn:foo:"}])
        )

      assert C14n.canon_name(attr) == "urn:foo:Blah"
    end

    test "resolves element namespace" do
      elem =
        xmlElement(
          name: :Blah,
          nsinfo: {"foo", "Blah"},
          namespace: xmlNamespace(nodes: [{"foo", :"urn:foo:"}])
        )

      assert C14n.canon_name(elem) == "urn:foo:Blah"
    end

    test "resolves default namespace from parsed XML" do
      doc = parse(~s(<foo:a xmlns:foo="urn:foo:"><b xmlns="urn:bar:"></b></foo:a>))
      assert C14n.canon_name(doc) == "urn:foo:a"

      [b_elem] = xmlElement(doc, :content) |> Enum.filter(&Record.is_record(&1, :xmlElement))
      assert C14n.canon_name(b_elem) == "urn:bar:b"
    end
  end

  describe "xml_safe_string/2" do
    test "handles atoms" do
      assert C14n.xml_safe_string(:foo) == ~c"foo"
    end

    test "handles binaries with newlines" do
      assert C14n.xml_safe_string("foo \ngeorge") == ~c"foo \ngeorge"
    end

    test "escapes special characters" do
      input = ~c"foo <" ++ [5] ++ ~c"> = & help"
      assert C14n.xml_safe_string(input) == ~c"foo &lt;&#x5;&gt; = &amp; help"
    end

    test "escapes control characters" do
      assert C14n.xml_safe_string(<<14>>) == ~c"&#xE;"
    end

    test "preserves quotes in non-quoted mode" do
      assert C14n.xml_safe_string(~c"\"foo\"") == ~c"\"foo\""
    end

    test "escapes carriage return" do
      assert C14n.xml_safe_string(~c"test\r\n") == ~c"test&#xD;\n"
    end

    test "preserves UTF-8" do
      string = :unicode.characters_to_list("バカの名前")
      assert C14n.xml_safe_string(string) == string
    end
  end

  describe "c14n/3" do
    test "W3C 3.1 - PIs, Comments, and Outside of Document Element" do
      doc =
        parse_doc(
          ~s(<?xml version="1.0"?>\n\n<?xml-stylesheet   href="doc.xsl"\n   type="text/xsl"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->)
        )

      without_comments =
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"

      assert C14n.c14n(doc, false) == without_comments

      with_comments =
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"

      assert C14n.c14n(doc, true) == with_comments
    end

    test "W3C 3.2 - Whitespace in Document Content" do
      doc =
        parse_doc(
          "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>"
        )

      target =
        "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>"

      assert C14n.c14n(doc, true) == target
    end

    test "W3C 3.3 - Start and End Tags" do
      doc =
        parse_doc(
          ~s(<!DOCTYPE doc [<!ATTLIST e9 attr CDATA "default">]>\n<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = "elem3"   id="elem3"   />\n   <e4   name="elem4"   id="elem4"   ></e4>\n   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"\n      xmlns:b="http://www.ietf.org"\n      xmlns:a="http://www.w3.org"\n      xmlns="http://example.org"/>\n   <e6 xmlns="" xmlns:a="http://www.w3.org">\n      <e7 xmlns="http://www.ietf.org">\n         <e8 xmlns="" xmlns:a="http://www.w3.org">\n            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>)
        )

      target =
        "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6>\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>"

      assert C14n.c14n(doc, true) == target
    end

    # xmerl normalizes DTD attributes (NMTOKENS, ID) during parsing,
    # so \r\n\t are already stripped before C14n processes the data.
    # The expected output reflects xmerl's DTD-normalized values rather
    # than the raw W3C 3.4 expected output.
    test "W3C 3.4 - Character Modifications and Character References" do
      doc =
        parse_doc(
          ~s(<!DOCTYPE doc [\n<!ATTLIST normId id ID #IMPLIED>\n<!ATTLIST normNames attr NMTOKENS #IMPLIED>\n]>\n<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>"0" && value<"10" ?"valid":"error"]]></compute>\n   <compute expr='value>"0" &amp;&amp; value&lt;"10" ?"valid":"error"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n   <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>\n   <normId id=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>)
        )

      # xmerl pre-normalizes DTD-typed attributes: NMTOKENS strips
      # leading/trailing whitespace and collapses inner whitespace to
      # single spaces; ID does the same. So \r\n\t are gone before C14n.
      target =
        "<doc>\n   <text>First line\n\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    ' \"></norm>\n   <normNames attr=\"A B\"></normNames>\n   <normId id=\"' '\"></normId>\n</doc>"

      assert C14n.c14n(doc, true) == target
    end

    test "default namespace handling" do
      doc =
        parse(
          ~s(<foo:a xmlns:foo="urn:foo:"><b xmlns="urn:bar:"><c xmlns="urn:bar:" /></b><c xmlns="urn:bar:"><d /></c><foo:e><f xmlns="urn:foo:"><foo:x>blah</foo:x></f></foo:e></foo:a>)
        )

      target =
        ~s(<foo:a xmlns:foo="urn:foo:"><b xmlns="urn:bar:"><c></c></b><c xmlns="urn:bar:"><d></d></c><foo:e><f xmlns="urn:foo:"><foo:x>blah</foo:x></f></foo:e></foo:a>)

      assert C14n.c14n(doc, true) == target
    end

    test "SAML response with default namespace" do
      doc =
        parse(
          ~s(<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_83dbf3f1-53c2-4f49-b294-7c19cbf2b77b" Version="2.0" IssueInstant="2013-10-30T11:15:47.517Z" Destination="https://10.10.18.25/saml/consume"><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_debe5f4e-4343-4f95-b997-89db5a483202" IssueInstant="2013-10-30T11:15:47.517Z"><Issuer>foo</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData NotOnOrAfter="2013-10-30T12:15:47.517Z" Recipient="https://10.10.18.25/saml/consume"/></SubjectConfirmation></Subject></Assertion></saml2p:Response>)
        )

      target =
        ~s(<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://10.10.18.25/saml/consume" ID="_83dbf3f1-53c2-4f49-b294-7c19cbf2b77b" IssueInstant="2013-10-30T11:15:47.517Z" Version="2.0"><Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_debe5f4e-4343-4f95-b997-89db5a483202" IssueInstant="2013-10-30T11:15:47.517Z" Version="2.0"><Issuer>foo</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"></NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData NotOnOrAfter="2013-10-30T12:15:47.517Z" Recipient="https://10.10.18.25/saml/consume"></SubjectConfirmationData></SubjectConfirmation></Subject></Assertion></saml2p:Response>)

      assert C14n.c14n(doc, true) == target
    end

    test "omit default namespace when prefixed" do
      doc = parse(~s(<foo:a xmlns:foo="urn:foo"><bar:b xmlns="urn:bar" xmlns:bar="urn:bar"><bar:c /></bar:b></foo:a>))

      target = ~s(<foo:a xmlns:foo="urn:foo"><bar:b xmlns:bar="urn:bar"><bar:c></bar:c></bar:b></foo:a>)
      assert C14n.c14n(doc, true) == target
    end

    test "inclusive namespaces" do
      doc =
        parse(
          ~s(<foo:a xmlns:foo="urn:foo:" xmlns:bar="urn:bar:"><foo:b bar:nothing="something">foo</foo:b></foo:a>)
        )

      target1 =
        ~s(<foo:a xmlns:foo="urn:foo:"><foo:b xmlns:bar="urn:bar:" bar:nothing="something">foo</foo:b></foo:a>)

      assert C14n.c14n(doc, false) == target1

      target2 =
        ~s(<foo:a xmlns:bar="urn:bar:" xmlns:foo="urn:foo:"><foo:b bar:nothing="something">foo</foo:b></foo:a>)

      assert C14n.c14n(doc, false, ["bar"]) == target2
    end

    test "don't duplicate namespaces" do
      doc =
        parse(
          ~s(<foo:a xmlns:foo="urn:foo:"><foo:b xmlns:bar="urn:bar:" bar:nothing="something">foo</foo:b></foo:a>)
        )

      target =
        ~s(<foo:a xmlns:foo="urn:foo:"><foo:b xmlns:bar="urn:bar:" bar:nothing="something">foo</foo:b></foo:a>)

      assert C14n.c14n(doc, false, ["foo", "bar"]) == target
    end
  end
end
