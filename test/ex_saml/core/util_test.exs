defmodule ExSaml.Core.UtilTest do
  use ExUnit.Case, async: true

  alias ExSaml.Core.Util

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(
    :xmlNamespace,
    Record.extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl")
  )

  # ---------------------------------------------------------------------------
  # datetime_to_saml/1
  # ---------------------------------------------------------------------------

  describe "datetime_to_saml/1" do
    test "converts an Erlang datetime tuple to a SAML timestamp string" do
      assert Util.datetime_to_saml({{2013, 5, 2}, {17, 26, 53}}) == "2013-05-02T17:26:53Z"
    end

    test "zero-pads single-digit month, day, hour, minute, second" do
      assert Util.datetime_to_saml({{2000, 1, 3}, {4, 5, 6}}) == "2000-01-03T04:05:06Z"
    end
  end

  # ---------------------------------------------------------------------------
  # saml_to_datetime/1
  # ---------------------------------------------------------------------------

  describe "saml_to_datetime/1" do
    test "parses a SAML timestamp string into an Erlang datetime tuple" do
      assert Util.saml_to_datetime("1990-11-23T18:01:01Z") == {{1990, 11, 23}, {18, 1, 1}}
    end

    test "accepts a charlist as input" do
      assert Util.saml_to_datetime(~c"2013-05-02T17:26:53Z") == {{2013, 5, 2}, {17, 26, 53}}
    end

    test "roundtrips with datetime_to_saml/1" do
      dt = {{2024, 12, 31}, {23, 59, 59}}
      assert dt == Util.saml_to_datetime(Util.datetime_to_saml(dt))
    end
  end

  # ---------------------------------------------------------------------------
  # unique_id/0
  # ---------------------------------------------------------------------------

  describe "unique_id/0" do
    test "starts with underscore and has reasonable length" do
      id = Util.unique_id()
      assert String.starts_with?(id, "_")
      # 16 random bytes -> 32 hex chars + 1 underscore prefix = 33
      assert String.length(id) == 33
    end

    test "generates different values on successive calls" do
      id1 = Util.unique_id()
      id2 = Util.unique_id()
      refute id1 == id2
    end
  end

  # ---------------------------------------------------------------------------
  # convert_fingerprints/1
  # ---------------------------------------------------------------------------

  describe "convert_fingerprints/1" do
    test "passes through raw binary fingerprints unchanged" do
      raw = <<0::128>>
      assert Util.convert_fingerprints([raw]) == [raw]
    end

    test "hex colon-separated fingerprints are decoded to binary" do
      hex_fp = "00:00:00:00:01:0A:03"
      [result] = Util.convert_fingerprints([hex_fp])
      assert result == <<0, 0, 0, 0, 1, 10, 3>>
    end

    test "SHA-typed fingerprints are decoded to {type, binary}" do
      data = <<0::160>>
      b64 = Base.encode64(data)
      sha_fp = "SHA:#{b64}"
      [result] = Util.convert_fingerprints([sha_fp])
      assert result == {:sha, data}
    end

    test "SHA256-typed fingerprints are decoded to {type, binary}" do
      data = :crypto.strong_rand_bytes(32)
      b64 = Base.encode64(data)
      sha256_fp = "SHA256:#{b64}"
      [result] = Util.convert_fingerprints([sha256_fp])
      assert result == {:sha256, data}
    end

    test "returns empty list for empty input" do
      assert Util.convert_fingerprints([]) == []
    end
  end

  # ---------------------------------------------------------------------------
  # build_nsinfo/2
  # ---------------------------------------------------------------------------

  describe "build_nsinfo/2" do
    test "sets nsinfo for colon-separated element name" do
      nsp = xmlNamespace()

      elem =
        xmlElement(
          name: :"saml:Assertion",
          attributes: [],
          content: []
        )

      result = Util.build_nsinfo(nsp, elem)
      assert xmlElement(result, :nsinfo) == {~c"saml", ~c"Assertion"}
    end

    test "does not set nsinfo for plain element name" do
      nsp = xmlNamespace()

      elem =
        xmlElement(
          name: :Assertion,
          attributes: [],
          content: []
        )

      result = Util.build_nsinfo(nsp, elem)
      # plain names get an empty list for nsinfo
      assert xmlElement(result, :nsinfo) == []
    end

    test "sets nsinfo on attributes with colon-separated names" do
      nsp = xmlNamespace()

      attr = xmlAttribute(name: :"xmlns:saml")

      elem =
        xmlElement(
          name: :Root,
          attributes: [attr],
          content: []
        )

      result = Util.build_nsinfo(nsp, elem)
      [result_attr] = xmlElement(result, :attributes)
      assert xmlAttribute(result_attr, :nsinfo) == {~c"xmlns", ~c"saml"}
    end

    test "recursively processes child elements" do
      nsp = xmlNamespace()

      child =
        xmlElement(
          name: :"saml:Subject",
          attributes: [],
          content: []
        )

      parent =
        xmlElement(
          name: :"saml:Assertion",
          attributes: [],
          content: [child]
        )

      result = Util.build_nsinfo(nsp, parent)
      [result_child] = xmlElement(result, :content)
      assert xmlElement(result_child, :nsinfo) == {~c"saml", ~c"Subject"}
    end

    test "passes through non-record nodes unchanged" do
      nsp = xmlNamespace()
      assert Util.build_nsinfo(nsp, "plain text") == "plain text"
    end
  end
end
