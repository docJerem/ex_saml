defmodule ExSaml.SPHandlerTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias ExSaml.{IdpData, SPHandler, Subject}

  # Minimal in-process stub for the cache configured via
  # `config :ex_saml, cache: …`. The real cache is a Nebulex backend, but for
  # unit-testing the `SPHandler` we only need `get/1`. The returned value is
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

  # Builds a fresh conn with the given session payload populated. Used by tests
  # that need to drive `validate_authresp/4`'s SP-initiated branch from
  # session-stored values (relay_state, idp_id, saml_nonce). Independent of the
  # default `:conn` provided by `setup` because each test needs its own session.
  defp build_conn(session) do
    secret = String.duplicate("a", 64)

    opts =
      Plug.Session.init(
        store: :cookie,
        key: "_test_session",
        signing_salt: "salt",
        encryption_salt: "esalt"
      )

    conn =
      :get
      |> conn("/")
      |> init_test_session(session)
      |> Map.put(:secret_key_base, secret)
      |> Plug.Session.call(opts)
      |> fetch_session()

    Enum.reduce(session, conn, fn {k, v}, acc -> put_session(acc, k, v) end)
  end

  defp idp_initiated_assertion, do: %{subject: %Subject{in_response_to: ""}}
  defp sp_initiated_assertion, do: %{subject: %Subject{in_response_to: "request-id-42"}}

  # ---------------------------------------------------------------------------
  # target_url/2
  # ---------------------------------------------------------------------------

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

  # ---------------------------------------------------------------------------
  # validate_authresp/4 — IdP-initiated
  # ---------------------------------------------------------------------------

  describe "validate_authresp/4 — IdP-initiated" do
    test "returns {:ok, :idp_initiated, nil} on success — regression test for #24" do
      idp = %IdpData{allow_idp_initiated_flow: true, allowed_target_urls: nil}

      assert {:ok, :idp_initiated, nil} =
               SPHandler.validate_authresp(build_conn(%{}), idp, idp_initiated_assertion(), "")
    end

    test "succeeds when relay_state is one of allowed_target_urls" do
      idp = %IdpData{
        allow_idp_initiated_flow: true,
        allowed_target_urls: ["https://app.example.com/dashboard"]
      }

      assert {:ok, :idp_initiated, nil} =
               SPHandler.validate_authresp(
                 build_conn(%{}),
                 idp,
                 idp_initiated_assertion(),
                 "https://app.example.com/dashboard"
               )
    end

    test "returns :idp_initiated_not_allowed when allow_idp_initiated_flow is false" do
      idp = %IdpData{allow_idp_initiated_flow: false}

      assert {:error, :idp_initiated_not_allowed} =
               SPHandler.validate_authresp(build_conn(%{}), idp, idp_initiated_assertion(), "")
    end

    test "returns :invalid_target_url when relay_state not in allowed_target_urls" do
      idp = %IdpData{
        allow_idp_initiated_flow: true,
        allowed_target_urls: ["https://app.example.com/dashboard"]
      }

      assert {:error, :invalid_target_url} =
               SPHandler.validate_authresp(
                 build_conn(%{}),
                 idp,
                 idp_initiated_assertion(),
                 "https://elsewhere.example.com/"
               )
    end
  end

  # ---------------------------------------------------------------------------
  # validate_authresp/4 — SP-initiated
  # ---------------------------------------------------------------------------

  describe "validate_authresp/4 — SP-initiated" do
    test "returns {:ok, :sp_initiated, nonce} on success" do
      idp = %IdpData{id: "idp-1"}

      conn =
        build_conn(%{
          "relay_state" => "rs-abc",
          "idp_id" => "idp-1",
          "saml_nonce" => "nonce-xyz"
        })

      assert {:ok, :sp_initiated, "nonce-xyz"} =
               SPHandler.validate_authresp(conn, idp, sp_initiated_assertion(), "rs-abc")
    end

    test "returns :invalid_relay_state when session relay_state does not match" do
      idp = %IdpData{id: "idp-1"}

      conn =
        build_conn(%{
          "relay_state" => "rs-different",
          "idp_id" => "idp-1",
          "saml_nonce" => "nonce-xyz"
        })

      assert {:error, :invalid_relay_state} =
               SPHandler.validate_authresp(conn, idp, sp_initiated_assertion(), "rs-abc")
    end

    test "returns :invalid_idp_id when session idp_id does not match" do
      idp = %IdpData{id: "idp-1"}

      conn =
        build_conn(%{
          "relay_state" => "rs-abc",
          "idp_id" => "idp-other",
          "saml_nonce" => "nonce-xyz"
        })

      assert {:error, :invalid_idp_id} =
               SPHandler.validate_authresp(conn, idp, sp_initiated_assertion(), "rs-abc")
    end
  end
end
