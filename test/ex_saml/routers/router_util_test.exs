defmodule ExSaml.RouterUtilTest do
  use ExUnit.Case, async: true

  alias ExSaml.RouterUtil

  # Review point 7: every redirect to the consumer's target URL goes through
  # append_query/3, so a target URL that already carries a query string keeps it.
  describe "append_query/3" do
    test "bare URL" do
      assert RouterUtil.append_query("/cb", "code", "abc") == "/cb?code=abc"

      assert RouterUtil.append_query("https://app.example.com/cb", "code", "abc") ==
               "https://app.example.com/cb?code=abc"
    end

    test "preserves an existing query string, appending after it" do
      assert RouterUtil.append_query("/cb?x=1", "code", "abc") == "/cb?x=1&code=abc"
      assert RouterUtil.append_query("/cb?x=1&y=2", "error_id", "t1") == "/cb?x=1&y=2&error_id=t1"
    end

    test "handles a trailing '?' and a fragment" do
      assert RouterUtil.append_query("/cb?", "code", "abc") == "/cb?code=abc"
      assert RouterUtil.append_query("/cb#top", "code", "abc") == "/cb?code=abc#top"
      assert RouterUtil.append_query("/cb?x=1#top", "code", "abc") == "/cb?x=1&code=abc#top"
    end

    test "encodes the value" do
      assert RouterUtil.append_query("/cb", "code", "a b&c=d") == "/cb?code=a+b%26c%3Dd"
      assert RouterUtil.append_query("/cb", "code", "Zm9v-_=") == "/cb?code=Zm9v-_%3D"
    end

    test "the decoded parameter round-trips" do
      value = "ab/cd+ef=gh&ij"
      url = RouterUtil.append_query("https://app.example.com/cb?x=1", "code", value)
      %URI{query: query} = URI.parse(url)
      assert URI.decode_query(query) == %{"x" => "1", "code" => value}
    end
  end
end
