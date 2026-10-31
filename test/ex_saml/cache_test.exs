defmodule ExSaml.CacheTest do
  # The cache is configured globally (`config :ex_saml, cache: …`).
  use ExUnit.Case, async: false

  alias ExSaml.{AssertionCache, AuthorizationCodeCache, RelayStateCache}

  # A real Nebulex 3 cache, so the ExSaml cache modules are exercised against
  # the Nebulex 3 API rather than a stub.
  defmodule TestCache do
    use Nebulex.Cache,
      otp_app: :ex_saml,
      adapter: Nebulex.Adapters.Local
  end

  setup do
    previous_cache = Application.get_env(:ex_saml, :cache)
    start_supervised!(TestCache)
    Application.put_env(:ex_saml, :cache, TestCache)

    on_exit(fn ->
      if previous_cache do
        Application.put_env(:ex_saml, :cache, previous_cache)
      else
        Application.delete_env(:ex_saml, :cache)
      end
    end)
  end

  describe "RelayStateCache" do
    test "returns the stored value as is, and nil for a missing key" do
      assert RelayStateCache.put("rs", %{idp_id: "idp"}, ttl: :timer.minutes(5)) == :ok

      assert RelayStateCache.get("rs") == %{idp_id: "idp"}
      assert RelayStateCache.get("missing") == nil
      assert RelayStateCache.get("missing")[:target_url] == nil
    end

    test "take/1 returns the value once, then nil" do
      RelayStateCache.put("rs", %{idp_id: "idp"}, ttl: :timer.minutes(5))

      assert RelayStateCache.take("rs") == %{idp_id: "idp"}
      assert RelayStateCache.take("rs") == nil
      assert RelayStateCache.get("rs") == nil
    end

    test "ttl/1 returns the remaining TTL, and nil for a missing key" do
      RelayStateCache.put("rs", %{}, ttl: :timer.minutes(5))

      assert RelayStateCache.ttl("rs") in 1..:timer.minutes(5)
      assert RelayStateCache.ttl("missing") == nil
    end

    test "delete/1 removes the entry" do
      RelayStateCache.put("rs", %{}, ttl: :timer.minutes(5))

      assert RelayStateCache.delete("rs") == :ok
      assert RelayStateCache.get("rs") == nil
    end

    test "keys do not collide with the other ExSaml caches" do
      RelayStateCache.put("key", :relay_state, ttl: :timer.minutes(5))
      AuthorizationCodeCache.put("key", :code)

      assert RelayStateCache.get("key") == :relay_state
      assert AuthorizationCodeCache.get("key") == :code
    end
  end

  describe "AuthorizationCodeCache" do
    test "put/3 applies the default 30 second TTL" do
      AuthorizationCodeCache.put("code", %{ex_saml_assertion_key: {"idp", "user"}})

      assert AuthorizationCodeCache.get("code") == %{ex_saml_assertion_key: {"idp", "user"}}
      assert ExSaml.Cache.ttl({AuthorizationCodeCache, "code"}) in 1..AuthorizationCodeCache.ttl()
    end

    test "take/1 makes a code single-use" do
      AuthorizationCodeCache.put("code", :value)

      assert AuthorizationCodeCache.take("code") == :value
      assert AuthorizationCodeCache.take("code") == nil
    end

    test "put_new!/3 stores a new code and raises when the code already exists" do
      assert AuthorizationCodeCache.put_new!("s3cret-code", :first) == true

      error =
        assert_raise Nebulex.Error, fn ->
          AuthorizationCodeCache.put_new!("s3cret-code", :second)
        end

      assert error.reason == :key_already_exists
      refute Exception.message(error) =~ "s3cret-code"

      assert AuthorizationCodeCache.get("s3cret-code") == :first
    end
  end

  describe "AssertionCache and ExSaml.State.Cache" do
    test "store, read, list and delete assertions" do
      key = {"idp", "user"}
      conn = %Plug.Conn{}

      assert ExSaml.State.Cache.put_assertion(conn, key, :assertion, []) == conn
      assert ExSaml.State.Cache.get_assertion(conn, key, []) == :assertion
      assert ExSaml.State.Cache.ttl_assertion(key) in 1..:timer.minutes(5)
      assert {{AssertionCache, key}, :assertion} in ExSaml.State.Cache.list_assertions()

      assert ExSaml.State.Cache.delete_assertion(conn, key, []) == conn
      assert ExSaml.State.Cache.get_assertion(conn, key, []) == nil
      assert ExSaml.State.Cache.ttl_assertion(key) == nil
    end

    test "take/1 returns the assertion once, then nil" do
      AssertionCache.put({"idp", "user"}, :assertion, ttl: :timer.minutes(5))

      assert AssertionCache.take({"idp", "user"}) == :assertion
      assert AssertionCache.take({"idp", "user"}) == nil
    end
  end

  describe "ExSaml.Assertion.get_from_code/1" do
    @tag :capture_log
    test "returns unauthorized for an unknown code" do
      assert ExSaml.Assertion.get_from_code("unknown") == {:error, :unauthorized}
    end
  end
end
