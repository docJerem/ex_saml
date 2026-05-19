defmodule ExSaml.SPHandlerTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  alias ExSaml.SPHandler

  # Minimal in-process stub for the cache configured via
  # `config :ex_saml, cache: …`. The real cache is a Nebulex backend, but for
  # unit-testing `target_url/2` we only need `get/1`. The returned value is
  # read from the process dictionary so each test can drive its own scenario.
  defmodule StubRelayCache do
    def get(_key), do: Process.get(:stub_relay_cache_value)
    def put(_key, _value, _opts), do: :ok
    def delete(_key), do: :ok
    def take(_key), do: nil
    def ttl(_key), do: nil
  end

  setup do
    previous_cache = Application.get_env(:ex_saml, :cache)
    previous_fallback = Application.get_env(:ex_saml, :fallback_target_url)
    Application.put_env(:ex_saml, :cache, StubRelayCache)

    on_exit(fn ->
      Process.delete(:stub_relay_cache_value)

      if previous_cache do
        Application.put_env(:ex_saml, :cache, previous_cache)
      else
        Application.delete_env(:ex_saml, :cache)
      end

      if previous_fallback do
        Application.put_env(:ex_saml, :fallback_target_url, previous_fallback)
      else
        Application.delete_env(:ex_saml, :fallback_target_url)
      end
    end)

    opts =
      Plug.Session.init(
        store: :cookie,
        key: "_ex_saml_sp_handler_test_session",
        encryption_salt: "salty enc",
        signing_salt: "salty signing",
        key_length: 64
      )

    conn =
      conn(:get, "/")
      |> Plug.Session.call(opts)
      |> fetch_session()

    {:ok, conn: conn}
  end

  describe "target_url/2" do
    test "returns the session target_url when set", %{conn: conn} do
      Process.put(:stub_relay_cache_value, %{target_url: "/from-cache"})
      conn = put_session(conn, "target_url", "/from-session")

      assert SPHandler.target_url(conn, "rls") == "/from-session"
    end

    test "returns the cached target_url when the session is empty", %{conn: conn} do
      Process.put(:stub_relay_cache_value, %{target_url: "/from-cache"})

      assert SPHandler.target_url(conn, "rls") == "/from-cache"
    end

    # Regression for issue #25: SAML error path crashed `redirect/3` because
    # `target_url/2` returned `nil` when both stores were empty, and
    # `Plug.Conn.put_resp_header/3` rejects a `nil` header value.
    test "falls back to the configured default when session and cache are empty", %{conn: conn} do
      Process.put(:stub_relay_cache_value, nil)

      assert SPHandler.target_url(conn, "rls") == "/"
      refute is_nil(SPHandler.target_url(conn, "rls"))
    end

    test "uses :fallback_target_url from app config when both stores are empty", %{conn: conn} do
      Application.put_env(:ex_saml, :fallback_target_url, "/sign-in")
      Process.put(:stub_relay_cache_value, nil)

      assert SPHandler.target_url(conn, "rls") == "/sign-in"
    end
  end
end
