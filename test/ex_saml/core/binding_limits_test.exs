defmodule ExSaml.Core.BindingLimitsTest do
  # `async: false`: these tests set `config :ex_saml, :safe_xml`, which is
  # process-global.
  use ExUnit.Case, async: false

  alias ExSaml.Core.Binding

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  @deflate "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"

  setup do
    previous = Application.get_env(:ex_saml, :safe_xml)
    test_pid = self()

    Application.put_env(:ex_saml, :safe_xml,
      max_document_size: 1024,
      on_error: fn ctx -> send(test_pid, {:safe_xml_error, ctx}) end
    )

    on_exit(fn ->
      if previous do
        Application.put_env(:ex_saml, :safe_xml, previous)
      else
        Application.delete_env(:ex_saml, :safe_xml)
      end
    end)

    :ok
  end

  # Compresses to a few dozen bytes, inflates to 4 KiB: above the 1 KiB limit
  # set in `setup`.
  defp oversized_deflate, do: :zlib.zip(String.duplicate(" ", 4096))

  describe "HTTP-Redirect (DEFLATE encoding)" do
    test "rejects a payload inflating beyond :max_document_size" do
      assert {:error, :invalid_xml} =
               Binding.decode_response(@deflate, Base.encode64(oversized_deflate()))

      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :too_large}}
    end

    test "rejects a payload that is not a DEFLATE stream" do
      assert {:error, :invalid_xml} =
               Binding.decode_response(@deflate, Base.encode64("<AuthnRequest/>"))

      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :invalid_deflate}}
    end

    test "returns an error on invalid base64 instead of raising" do
      assert {:error, :invalid_xml} = Binding.decode_response(@deflate, "!!!")
    end
  end

  describe "HTTP-POST (base64 only)" do
    test "accepts an uncompressed payload" do
      assert {:ok, root} = Binding.decode_response("", Base.encode64("<Response/>"))
      assert xmlElement(root, :name) == :Response
    end

    test "still accepts a compressed payload within the limit" do
      payload = "<Response/>" |> :zlib.zip() |> Base.encode64()

      assert {:ok, root} = Binding.decode_response("", payload)
      assert xmlElement(root, :name) == :Response
    end

    test "rejects a compressed payload inflating beyond :max_document_size" do
      assert {:error, :invalid_xml} =
               Binding.decode_response("", Base.encode64(oversized_deflate()))

      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :too_large}}
    end

    test "rejects an uncompressed payload larger than :max_document_size" do
      xml = "<Response>" <> String.duplicate("a", 1024) <> "</Response>"

      assert {:error, :invalid_xml} = Binding.decode_response("", Base.encode64(xml))
      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :too_large}}
    end

    test "rejects a payload with a DOCTYPE" do
      xml = "<!DOCTYPE Response><Response/>"

      assert {:error, :invalid_xml} = Binding.decode_response("", Base.encode64(xml))
      assert_receive {:safe_xml_error, %{kind: :rejected, payload: :doctype}}
    end

    test "returns an error on invalid base64 instead of raising" do
      assert {:error, :invalid_xml} = Binding.decode_response("", "!!!")
    end
  end
end
