defmodule ExSaml.Core.Xml.SafeXmlTest do
  use ExUnit.Case, async: false

  # Exhausting the atom budget logs a warning.
  @moduletag :capture_log

  alias ExSaml.Core.Xml.SafeXml
  alias ExSaml.Core.Xml.SafeXml.{AtomBudget, KnownNames, Prescan}

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))
  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  # `async: false` because these tests mutate
  # `Application.put_env(:ex_saml, :safe_xml, ...)`, which is process-global,
  # and read the node-wide atom budget.

  @saml_ns ~s(xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
             ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion")

  setup do
    previous = Application.get_env(:ex_saml, :safe_xml)

    on_exit(fn ->
      if previous do
        Application.put_env(:ex_saml, :safe_xml, previous)
      else
        Application.delete_env(:ex_saml, :safe_xml)
      end
    end)

    :ok
  end

  # Configures `opts` plus a hook forwarding every failure to the test process.
  defp configure(opts) do
    test_pid = self()
    hook = fn ctx -> send(test_pid, {:safe_xml_error, ctx}) end
    Application.put_env(:ex_saml, :safe_xml, Keyword.put(opts, :on_error, hook))
  end

  defp assert_rejected(doc, reason) do
    assert {:error, :invalid_xml} = SafeXml.scan(doc)
    assert_receive {:safe_xml_error, %{reason: :invalid_xml, kind: :rejected, payload: ^reason}}
    refute_receive {:safe_xml_error, _}, 10
  end

  # A name that is not an atom yet (no atom is created by building it).
  defp fresh_name(prefix), do: "#{prefix}#{System.unique_integer([:positive])}"

  defp refute_atom(name) do
    assert_raise ArgumentError, fn -> String.to_existing_atom(name) end
  end

  # Leaves exactly `remaining` units in the node-wide atom budget.
  defp budget_left(remaining, opts \\ []) do
    configure(Keyword.put(opts, :max_new_atoms, AtomBudget.used() + remaining))
  end

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

  describe "scan/1 — DOCTYPE declarations" do
    @tag :tmp_dir
    test "rejects a DOCTYPE naming an external DTD before the parser runs", %{tmp_dir: tmp_dir} do
      # Not DTD syntax: had the parser opened the file, it would report a
      # parse failure (kind :exit) instead of a rejection.
      path = Path.join(tmp_dir, "external.dtd")
      File.write!(path, "not a dtd\n")
      configure([])

      assert_rejected(~s(<?xml version="1.0"?><!DOCTYPE root SYSTEM "#{path}"><root/>), :doctype)
    end

    test "rejects a DOCTYPE with an internal subset" do
      configure([])
      assert_rejected(~s(<!DOCTYPE root [<!ELEMENT root ANY>]><root/>), :doctype)
    end

    test "rejects a DOCTYPE without a subset" do
      configure([])
      assert_rejected("<!DOCTYPE root><root/>", :doctype)
    end

    test "rejects a markup declaration outside a DOCTYPE" do
      configure([])
      assert_rejected(~s(<root><!ENTITY name "value"></root>), :doctype)
    end

    test "accepts declaration-like text inside comments and CDATA sections" do
      doc = "<root><!-- <!DOCTYPE a> --><![CDATA[<!DOCTYPE b> &c;]]></root>"
      assert {:ok, _} = SafeXml.scan(doc)
    end
  end

  describe "scan/1 — entity references" do
    test "rejects a reference to an entity in character data" do
      configure([])
      assert_rejected("<root>&name;</root>", :entity_reference)
    end

    test "rejects a reference to an entity in an attribute value" do
      configure([])
      assert_rejected(~s(<root a="&name;"/>), :entity_reference)
    end

    test "accepts the predefined entities and character references" do
      doc = ~s(<root a="&lt;&#65;&amp;">&gt;&quot;&apos;&#x42;</root>)
      assert {:ok, root} = SafeXml.scan(doc)
      assert [xmlText(value: ~c">\"'B")] = xmlElement(root, :content)
    end
  end

  describe "scan/1 — document size" do
    test "accepts a document of exactly :max_document_size bytes" do
      configure(max_document_size: 64)
      doc = "<root>" <> String.duplicate("a", 64 - 13) <> "</root>"
      assert byte_size(doc) == 64
      assert {:ok, _} = SafeXml.scan(doc)
    end

    test "rejects a document larger than :max_document_size bytes" do
      configure(max_document_size: 64)
      assert_rejected("<root>" <> String.duplicate("a", 65 - 13) <> "</root>", :too_large)
    end
  end

  describe "scan/1 — encodings" do
    test "rejects a UTF-16 document" do
      configure([])

      doc =
        <<0xFE, 0xFF>> <>
          :unicode.characters_to_binary(~s(<?xml version="1.0"?><root/>), :utf8, {:utf16, :big})

      assert_rejected(doc, :unsupported_encoding)
    end

    test "rejects a declared encoding other than UTF-8, US-ASCII or ISO-8859-1" do
      configure([])
      assert_rejected(~s(<?xml version="1.0" encoding="UTF-16"?><root/>), :unsupported_encoding)
    end

    test "accepts a document declared as ISO-8859-1" do
      decl = ~s(<?xml version="1.0" encoding="ISO-8859-1"?>)
      doc = decl <> "<root>caf" <> <<0xE9>> <> "</root>"
      assert {:ok, root} = SafeXml.scan(doc)
      assert [xmlText(value: ~c"café")] = xmlElement(root, :content)
    end

    test "accepts a UTF-8 byte order mark" do
      assert {:ok, _} = SafeXml.scan(<<0xEF, 0xBB, 0xBF, "<root/>">>)
    end
  end

  describe "scan/1 — atom bound" do
    test "a document made of the SAML vocabulary draws nothing from the budget" do
      budget_left(0)
      used = AtomBudget.used()

      doc = """
      <samlp:Response #{@saml_ns} ID="_1" Version="2.0" xml:lang="en">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:SignedInfo><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:SignedInfo>
        </ds:Signature>
        <saml:EncryptedAssertion>
          <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"/>
        </saml:EncryptedAssertion>
        <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <AttributeStatement><Attribute Name="mail"><AttributeValue xsi:type="xs:string">a@b.c</AttributeValue></Attribute></AttributeStatement>
        </Assertion>
      </samlp:Response>
      """

      assert {:ok, _} = SafeXml.scan(doc)
      assert AtomBudget.used() == used
    end

    test "names that are already atoms draw nothing from the budget" do
      budget_left(0)
      assert {:ok, _} = SafeXml.scan(~s(<Elixir.Kernel ok="true"/>))
    end

    test "a new name draws once from the budget, then is free" do
      name = fresh_name("vendor")
      budget_left(1)
      used = AtomBudget.used()

      assert {:ok, _} = SafeXml.scan("<#{name}/>")
      assert AtomBudget.used() == used + 1

      assert {:ok, _} = SafeXml.scan("<#{name}/>")
      assert AtomBudget.used() == used + 1
    end

    test "rejects a document whose new names exceed the budget, before creating any atom" do
      names = for _ <- 1..3, do: fresh_name("vendor")
      budget_left(2)
      used = AtomBudget.used()

      doc =
        "<samlp:Response #{@saml_ns}>" <> Enum.map_join(names, &"<#{&1}/>") <> "</samlp:Response>"

      assert_rejected(doc, :atom_budget_exhausted)
      assert AtomBudget.used() == used
      Enum.each(names, &refute_atom/1)
    end

    test "counts every name the parser would turn into an atom" do
      name = fresh_name("n")

      for doc <- [
            # element name, in an end tag only
            "<samlp:Response #{@saml_ns}></#{name}>",
            # attribute name
            ~s(<samlp:Response #{@saml_ns} #{name}="1"/>),
            # local part of a qualified name
            "<saml:#{name} #{@saml_ns}/>",
            # namespace URI bound to a prefix, and as default namespace
            ~s(<samlp:Response xmlns:samlp="urn:#{name}"/>),
            ~s(<Response xmlns="urn:#{name}"/>),
            # processing-instruction target
            "<?#{name} data?><Response/>"
          ] do
        budget_left(0)
        assert_rejected(doc, :atom_budget_exhausted)
      end

      refute_atom(name)
      refute_atom("urn:" <> name)
    end

    test "concurrent documents cannot together exceed the budget" do
      names = for _ <- 1..20, do: fresh_name("vendor")
      budget_left(5)
      used = AtomBudget.used()

      results =
        names
        |> Task.async_stream(&SafeXml.scan("<#{&1}/>"), max_concurrency: 20)
        |> Enum.map(fn {:ok, result} -> result end)

      assert Enum.count(results, &match?({:ok, _}, &1)) == 5
      assert AtomBudget.used() == used + 5
    end

    test ":extra_prefixes makes an IdP's own prefix known" do
      prefix = fresh_name("ns")

      doc =
        ~s(<#{prefix}:Response xmlns:#{prefix}="urn:oasis:names:tc:SAML:2.0:protocol">) <>
          ~s(<#{prefix}:Status/></#{prefix}:Response>)

      budget_left(0)
      assert_rejected(doc, :atom_budget_exhausted)

      budget_left(0, extra_prefixes: [prefix])
      assert {:ok, _} = SafeXml.scan(doc)
    end

    test ":extra_names makes vendor extension names known" do
      local = fresh_name("Extension")
      uri = "urn:" <> fresh_name("vendor")
      doc = ~s(<samlp:Response #{@saml_ns} xmlns:vnd="#{uri}"><vnd:#{local}/></samlp:Response>)

      budget_left(0)
      assert_rejected(doc, :atom_budget_exhausted)

      budget_left(0, extra_names: ["xmlns:vnd", uri, "vnd:" <> local, local])
      assert {:ok, _} = SafeXml.scan(doc)
    end
  end

  describe "scan/1 — existing fixtures" do
    @fixtures Path.wildcard("test/data/*.xml") ++
                Path.wildcard("test/fixtures/metadata/*.xml") ++
                Path.wildcard("test/ex_saml/fixtures/*.xml")

    @malformed_fixtures ["test/fixtures/metadata/invalid_xml.xml"]

    test "every well-formed fixture still parses" do
      assert length(@fixtures) > 20

      for path <- @fixtures -- @malformed_fixtures do
        assert {:ok, root} = path |> File.read!() |> SafeXml.scan(), path
        assert Record.is_record(root, :xmlElement), path
      end
    end

    test "the malformed fixture is still rejected" do
      for path <- @malformed_fixtures do
        assert {:error, :invalid_xml} = path |> File.read!() |> SafeXml.scan(), path
      end
    end

    test "real IdP metadata and a signed Response use only the built-in vocabulary" do
      for path <- Path.wildcard("test/data/*.xml") ++ Path.wildcard("test/ex_saml/fixtures/*.xml") do
        assert {:ok, names} = path |> File.read!() |> Prescan.names(), path
        assert Enum.reject(names, &KnownNames.known?/1) == [], path
      end
    end
  end

  describe "inflate/1" do
    test "inflates a DEFLATE stream" do
      assert {:ok, "<root/>"} = SafeXml.inflate(:zlib.zip("<root/>"))
    end

    test "stops at :max_document_size and rejects the stream" do
      configure(max_document_size: 1024)
      data = :zlib.zip(String.duplicate(" ", 4096))

      assert {:error, :invalid_xml} = SafeXml.inflate(data)
      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :too_large}}
    end

    test "rejects data that is not a DEFLATE stream" do
      configure([])
      assert {:error, :invalid_xml} = SafeXml.inflate("<root/>")
      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :invalid_deflate}}
    end

    test "rejects a truncated DEFLATE stream" do
      configure([])
      data = :zlib.zip(String.duplicate("<root/>", 1000))

      assert {:error, :invalid_xml} = SafeXml.inflate(binary_part(data, 0, 10))
      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :invalid_deflate}}
    end
  end

  describe "inflate_if_deflated/1" do
    test "inflates a DEFLATE stream" do
      assert {:ok, "<root/>"} = SafeXml.inflate_if_deflated(:zlib.zip("<root/>"))
    end

    test "returns data that is not a DEFLATE stream unchanged, without reporting it" do
      configure([])
      assert {:ok, "<root/>"} = SafeXml.inflate_if_deflated("<root/>")
      refute_receive {:safe_xml_error, _}, 10
    end

    test "rejects a DEFLATE stream inflating beyond :max_document_size" do
      configure(max_document_size: 1024)
      data = :zlib.zip(String.duplicate(" ", 4096))

      assert {:error, :invalid_xml} = SafeXml.inflate_if_deflated(data)
      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :too_large}}
    end
  end

  describe ":on_error hook" do
    setup do
      previous = Application.get_env(:ex_saml, :safe_xml)

      on_exit(fn ->
        if previous do
          Application.put_env(:ex_saml, :safe_xml, previous)
        else
          Application.delete_env(:ex_saml, :safe_xml)
        end
      end)

      :ok
    end

    test "is invoked once per parse failure with a context map" do
      test_pid = self()

      Application.put_env(:ex_saml, :safe_xml,
        on_error: fn ctx -> send(test_pid, {:ctx, ctx}) end
      )

      assert {:error, :invalid_xml} = SafeXml.scan("<broken")

      assert_receive {:ctx, %{reason: :invalid_xml, kind: kind, payload: payload}}
      assert kind in [:error, :exit, :throw, :rejected]
      assert payload != nil
      refute_receive {:ctx, _}, 50
    end

    test "reports a parser failure with the parser's exit reason" do
      test_pid = self()

      Application.put_env(:ex_saml, :safe_xml,
        on_error: fn ctx -> send(test_pid, {:ctx, ctx}) end
      )

      assert {:error, :invalid_xml} = SafeXml.scan("<root></other>")

      assert_receive {:ctx, %{reason: :invalid_xml, kind: :exit, payload: {:fatal, _}}}
    end

    test "reports a document refused before parsing with kind :rejected" do
      test_pid = self()

      Application.put_env(:ex_saml, :safe_xml,
        on_error: fn ctx -> send(test_pid, {:ctx, ctx}) end
      )

      assert {:error, :invalid_xml} = SafeXml.scan("<!DOCTYPE root><root/>")

      assert_receive {:ctx, %{reason: :invalid_xml, kind: :rejected, payload: :doctype}}
    end

    test "is not invoked on successful parses" do
      test_pid = self()
      Application.put_env(:ex_saml, :safe_xml, on_error: fn _ctx -> send(test_pid, :called) end)

      assert {:ok, _} = SafeXml.scan("<root/>")

      refute_receive :called, 50
    end

    test "swallows handler exceptions and still returns the error tuple" do
      Application.put_env(:ex_saml, :safe_xml, on_error: fn _ctx -> raise "handler boom" end)

      assert {:error, :invalid_xml} = SafeXml.scan("<broken")
    end

    test "is a no-op when no handler is configured" do
      Application.delete_env(:ex_saml, :safe_xml)
      assert {:error, :invalid_xml} = SafeXml.scan("<broken")
    end

    test "is a no-op when the configured value is not an arity-1 function" do
      Application.put_env(:ex_saml, :safe_xml, on_error: :not_a_function)
      assert {:error, :invalid_xml} = SafeXml.scan("<broken")

      Application.put_env(:ex_saml, :safe_xml, on_error: fn -> :wrong_arity end)
      assert {:error, :invalid_xml} = SafeXml.scan("<broken")
    end
  end
end
