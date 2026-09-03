defmodule ExSaml.Debug.JSONTest do
  use ExUnit.Case, async: true

  alias ExSaml.Debug.JSON
  alias ExSaml.Error

  # Every encoder assertion round-trips through a real parser. Jason is present
  # in the test environment, so the hand-rolled encoder is checked against it
  # rather than trusted.
  defp roundtrip(term),
    do: term |> JSON.encode_to_iodata!() |> IO.iodata_to_binary() |> Jason.decode!()

  describe "normalize/1" do
    test "atoms become strings, nil and booleans stay themselves" do
      assert JSON.normalize(:bad_digest) == "bad_digest"
      assert JSON.normalize(nil) == nil
      assert JSON.normalize(true) == true
      assert JSON.normalize(false) == false
    end

    test "module atoms lose the Elixir prefix" do
      assert JSON.normalize(ExSaml.Debug) == "ExSaml.Debug"
    end

    test "numbers pass through" do
      assert JSON.normalize(42) == 42
      assert JSON.normalize(1.5) == 1.5
    end

    test "date and time structs become ISO 8601" do
      assert JSON.normalize(~U[2026-09-03 12:14:03Z]) == "2026-09-03T12:14:03Z"
      assert JSON.normalize(~N[2026-09-03 12:14:03]) == "2026-09-03T12:14:03"
      assert JSON.normalize(~D[2026-09-03]) == "2026-09-03"
      assert JSON.normalize(~T[12:14:03]) == "12:14:03"
    end

    test "tuples become arrays" do
      assert JSON.normalize({:idp, "acme"}) == ["idp", "acme"]
      assert JSON.normalize({1, {2, 3}}) == [1, [2, 3]]
    end

    test "keyword lists become objects" do
      assert JSON.normalize(email: "a@b.c", groups: ["x"]) == %{
               "email" => "a@b.c",
               "groups" => ["x"]
             }
    end

    test "an empty list stays a list, not an empty string" do
      # `[]` is also the empty charlist; getting this wrong turns every empty
      # attribute list into `""`.
      assert JSON.normalize([]) == []
      assert JSON.normalize(%{attributes: []}) == %{"attributes" => []}
    end

    test "printable charlists become strings, others arrays of integers" do
      assert JSON.normalize(~c"acme") == "acme"
      assert JSON.normalize([0, 1, 2]) == [0, 1, 2]
    end

    test "maps with atom keys become objects with string keys" do
      assert JSON.normalize(%{capture: :on_error}) == %{"capture" => "on_error"}
    end

    test "non-atom, non-binary keys are inspected" do
      assert JSON.normalize(%{{:a, 1} => true}) == %{"{:a, 1}" => true}
    end

    test "binaries that are not text become base64" do
      assert JSON.normalize(<<0xFF, 0xFE>>) == %{"base64" => Base.encode64(<<0xFF, 0xFE>>)}
    end

    test "valid UTF-8 stays a string" do
      assert JSON.normalize("héllo 🎉") == "héllo 🎉"
    end

    test "xmerl records are inspected rather than expanded" do
      record = {:xmlElement, :Assertion, :Assertion, [], {:xmlNamespace, [], []}, [], 1, [], []}

      assert %{"inspect" => inspected} = JSON.normalize(record)
      assert inspected =~ "xmlElement"
    end

    test "structs with no JSON meaning are inspected and truncated" do
      assert %{"inspect" => inspected} = JSON.normalize(%URI{host: "example.com"})
      assert inspected =~ "example.com"
      assert String.length(inspected) <= 1024
    end

    test "an ExSaml.Error renders its fields but never its trace" do
      error = %Error{reason: :bad_digest, scope: :assertion, trace: [{:decode_result, %{}}]}

      normalized = JSON.normalize(error)

      assert normalized["reason"] == "bad_digest"
      assert normalized["scope"] == "assertion"
      refute Map.has_key?(normalized, "trace")
    end

    test "pids and functions are inspected rather than crashing the encoder" do
      assert %{"inspect" => _} = JSON.normalize(self())
      assert %{"inspect" => _} = JSON.normalize(fn -> :ok end)
    end

    test "runaway nesting is cut off" do
      deep = Enum.reduce(1..50, :leaf, fn _, acc -> %{next: acc} end)

      assert deep |> JSON.normalize() |> inspect() =~ "…"
    end
  end

  describe "encode_to_iodata!/1" do
    test "encodes the JSON data model" do
      assert roundtrip(%{a: 1, b: [true, false, nil], c: "x"}) == %{
               "a" => 1,
               "b" => [true, false, nil],
               "c" => "x"
             }
    end

    test "nil is null, not the string \"nil\"" do
      assert roundtrip(%{global: nil}) == %{"global" => nil}
    end

    test "escapes quotes, backslashes and control characters" do
      assert roundtrip("a\"b\\c\nd\te\r\bf\f") == "a\"b\\c\nd\te\r\bf\f"
      assert roundtrip(<<0x01, ?a>>) == <<0x01, ?a>>
    end

    test "leaves forward slashes alone" do
      assert IO.iodata_to_binary(JSON.encode_to_iodata!("/api/sp")) == "\"/api/sp\""
    end

    test "handles multi-byte characters" do
      assert roundtrip("héllo 🎉 日本") == "héllo 🎉 日本"
    end

    test "handles a payload-sized base64 blob" do
      blob = 8_000 |> :crypto.strong_rand_bytes() |> Base.encode64()

      assert roundtrip(%{base64: blob}) == %{"base64" => blob}
    end

    test "encodes an empty object and an empty array" do
      assert roundtrip(%{}) == %{}
      assert roundtrip([]) == []
    end

    test "encodes a whole trace event" do
      event = %{
        event: :validation_check,
        at: ~U[2026-09-03 12:14:03Z],
        node: :"app@10.0.0.7",
        data: %{check: :bad_issuer, enforced: false, expected: ~c"https://idp", actual: nil}
      }

      assert roundtrip(event) == %{
               "event" => "validation_check",
               "at" => "2026-09-03T12:14:03Z",
               "node" => "app@10.0.0.7",
               "data" => %{
                 "check" => "bad_issuer",
                 "enforced" => false,
                 "expected" => "https://idp",
                 "actual" => nil
               }
             }
    end
  end

  describe "decode/1" do
    test "decodes an object" do
      assert JSON.decode(~s({"ttl_ms":1800000,"capture":"always"})) ==
               {:ok, %{"ttl_ms" => 1_800_000, "capture" => "always"}}
    end

    test "reports malformed JSON rather than raising" do
      assert JSON.decode("{not json") == {:error, :invalid_json}
    end

    test "a configured decoder wins over the detected one" do
      Application.put_env(:ex_saml, :debug_api, json_decoder: {__MODULE__, :stub_decode})
      on_exit(fn -> Application.delete_env(:ex_saml, :debug_api) end)

      assert JSON.decode("anything") == {:ok, %{"stub" => true}}
    end
  end

  def stub_decode(_body), do: {:ok, %{"stub" => true}}
end
