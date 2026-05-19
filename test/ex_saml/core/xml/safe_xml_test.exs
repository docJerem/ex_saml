defmodule ExSaml.Core.Xml.SafeXmlTest do
  use ExUnit.Case, async: false

  alias ExSaml.Core.Xml.SafeXml

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  # `async: false` because tests in the `on_error hook` describe mutate
  # `Application.put_env(:ex_saml, :safe_xml, ...)`, which is process-global.

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
      assert kind in [:error, :exit, :throw]
      assert payload != nil
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
