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

    test "traces the provenance of each value in debug mode" do
      ExSaml.StubCache.install()
      ExSaml.Debug.enable(idp_id: "idp-1")
      Process.put(:stub_relay_cache_value, nil)
      idp = %IdpData{id: "idp-1"}

      conn = build_conn(%{"relay_state" => "rs-abc", "idp_id" => "idp-1"})

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, :sp_initiated, nil} =
                   SPHandler.validate_authresp(conn, idp, sp_initiated_assertion(), "rs-abc")
        end)

      assert log =~ "[ExSaml.Debug] validate_authresp_result"
      assert log =~ "relay_state_source: :session"
      assert log =~ "saml_nonce_source: :none"
    end
  end

  # ---------------------------------------------------------------------------
  # consume_signin_response/1 — failure path issues an error_id
  # ---------------------------------------------------------------------------

  defp acs_conn(idp_id, body \\ %{}, session \\ %{}) do
    secret = String.duplicate("a", 64)

    opts =
      Plug.Session.init(
        store: :cookie,
        key: "_test_session",
        signing_salt: "salt",
        encryption_salt: "esalt"
      )

    :post
    |> conn("/sso/consume/#{idp_id}", body)
    |> Map.update!(:params, &Map.put(&1, "idp_id", idp_id))
    |> Map.put(:secret_key_base, secret)
    |> Plug.Session.call(opts)
    |> fetch_session()
    |> then(fn c -> Enum.reduce(session, c, fn {k, v}, acc -> put_session(acc, k, v) end) end)
  end

  defp error_id_from(conn) do
    [location] = get_resp_header(conn, "location")
    %URI{query: query} = URI.parse(location)
    {location, URI.decode_query(query)["error_id"]}
  end

  # Stands in for a cache whose backend is down (or is simply not configured):
  # every operation raises. The consume path must survive it.
  defmodule RaisingCache do
    def get(_key), do: raise("cache unavailable")
    def put(_key, _value, _opts), do: raise("cache unavailable")
    def put_new!(_key, _value, _opts), do: raise("cache unavailable")
    def take(_key), do: raise("cache unavailable")
    def delete(_key), do: raise("cache unavailable")
    def ttl(_key), do: raise("cache unavailable")
    def all(_query, _opts), do: raise("cache unavailable")
  end

  describe "consume_signin_response/1 failure path" do
    alias ExSaml.{Core.SpConfig, Debug, Error}

    setup do
      ExSaml.StubCache.install()
      Application.delete_env(:ex_saml, :debug)
      Application.delete_env(:ex_saml, :debug_runtime)
      previous_idps = Application.get_env(:ex_saml, :identity_providers)

      idp = %IdpData{
        id: "idp-1",
        sp_config: %SpConfig{
          metadata_uri: "https://sp.example.com/metadata",
          consume_uri: "https://sp.example.com/consume"
        }
      }

      Application.put_env(:ex_saml, :identity_providers, %{
        "idp-1" => idp,
        "broken" => %IdpData{id: "broken", sp_config: nil}
      })

      on_exit(fn ->
        if previous_idps,
          do: Application.put_env(:ex_saml, :identity_providers, previous_idps),
          else: Application.delete_env(:ex_saml, :identity_providers)
      end)

      :ok
    end

    test "unknown idp_id -> redirect with a redeemable error_id, legacy session entry kept" do
      conn = SPHandler.consume_signin_response(acs_conn("nope"))

      assert conn.status == 302
      {location, error_id} = error_id_from(conn)
      assert location == "/?error_id=#{error_id}"
      assert get_session(conn, "ex_saml_error") == {:error, {:unknown_idp, "nope"}}

      # The idp lookup fails before the flow context is established, so the id
      # has to be threaded in explicitly rather than read back from the process.
      assert {:ok,
              %Error{
                reason: {:unknown_idp, "nope"},
                step: :idp_lookup,
                idp_id: "nope",
                details: nil
              }} = Error.get_from_id(error_id)

      assert {:error, :not_found} = Error.get_from_id(error_id)
    end

    test "params without an idp_id fail closed with a 403, not a FunctionClauseError" do
      conn =
        SPHandler.consume_signin_response(
          acs_conn("idp-1")
          |> Map.update!(:params, &Map.delete(&1, "idp_id"))
        )

      assert conn.status == 403
      assert conn.resp_body == "invalid_request"
    end

    test "a raising cache still redirects — the error redirect cannot itself 500" do
      Application.put_env(:ex_saml, :cache, RaisingCache)
      on_exit(fn -> Application.put_env(:ex_saml, :cache, ExSaml.StubCache) end)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("nope"))

          # No error_id — it could not be stored — but the browser is still
          # redirected and the legacy session entry still carries the reason.
          assert conn.status == 302
          assert get_resp_header(conn, "location") == ["/"]
          assert get_session(conn, "ex_saml_error") == {:error, {:unknown_idp, "nope"}}
        end)

      assert log =~ "could not store the error"
    end

    test "an unstorable error and an unusable target url degrade to a 403, never an exception" do
      Application.put_env(:ex_saml, :cache, RaisingCache)
      on_exit(fn -> Application.put_env(:ex_saml, :cache, ExSaml.StubCache) end)

      ExUnit.CaptureLog.capture_log(fn ->
        conn =
          SPHandler.consume_signin_response(
            acs_conn("nope", %{}, %{"target_url" => "https://app.example.com/cb\nInjected: 1"})
          )

        assert conn.status == 403
        assert conn.resp_body == "access_denied"
      end)
    end

    test "missing SAMLResponse -> :missing_saml_response with step :decode" do
      conn = SPHandler.consume_signin_response(acs_conn("idp-1", %{"RelayState" => "rs-1"}))

      {_location, error_id} = error_id_from(conn)

      assert {:ok,
              %Error{
                reason: :missing_saml_response,
                step: :decode,
                idp_id: "idp-1",
                relay_state: "rs-1"
              }} =
               Error.get_from_id(error_id)
    end

    test "target_url from session gets the error_id appended, preserving its query" do
      conn =
        SPHandler.consume_signin_response(
          acs_conn("idp-1", %{}, %{"target_url" => "https://app.example.com/cb?x=1"})
        )

      {location, error_id} = error_id_from(conn)
      assert location == "https://app.example.com/cb?error_id=#{error_id}&x=1"
    end

    test "an exception while consuming fails closed with an error_id (never a bare 500)" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("broken", %{"SAMLResponse" => "x"}))
          assert conn.status == 302
          {_, error_id} = error_id_from(conn)

          assert {:ok, %Error{reason: {:exception, message}, step: :unexpected}} =
                   Error.get_from_id(error_id)

          assert is_binary(message)
        end)

      assert log =~ "consume_signin_response crashed"
    end

    test "with debug off the exception reason and the log carry only the type" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("broken", %{"SAMLResponse" => "x"}))
          {_, error_id} = error_id_from(conn)

          assert {:ok, %Error{reason: {:exception, message}}} = Error.get_from_id(error_id)

          # Exception messages embed the value that caused them, which on this
          # path is routinely the decoded assertion. Type only, no message.
          refute message =~ ":"
          assert message =~ ~r/Error$/
        end)

      assert log =~ "enable ExSaml.Debug for the full report"
      refute log =~ "** (stacktrace)"
    end

    test "with debug on the exception reason carries a truncated message" do
      Debug.enable(idp_id: "broken")

      ExUnit.CaptureLog.capture_log(fn ->
        conn = SPHandler.consume_signin_response(acs_conn("broken", %{"SAMLResponse" => "x"}))
        {_, error_id} = error_id_from(conn)

        assert {:ok, %Error{reason: {:exception, message}}} = Error.get_from_id(error_id)
        assert message =~ ":"
        assert String.length(message) < 400
      end)
    end

    test "in debug mode the error carries the flow report" do
      Debug.enable(idp_id: "idp-1")

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("idp-1", %{"RelayState" => "rs-2"}))
          {_, error_id} = error_id_from(conn)

          assert {:ok, %Error{details: details, debug_id: debug_id}} = Error.get_from_id(error_id)
          assert is_binary(debug_id)

          steps = Enum.map(details, &elem(&1, 0))
          assert :response_received in steps
          assert :decode_result in steps
        end)

      assert log =~ "[ExSaml.Debug] response_received"
      assert log =~ "[ExSaml.Debug] error_issued"
    end

    test "without debug nothing is logged and details stay nil" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("idp-1"))
          {_, error_id} = error_id_from(conn)
          assert {:ok, %Error{details: nil, debug_id: nil}} = Error.get_from_id(error_id)
        end)

      refute log =~ "[ExSaml.Debug]"
    end
  end
end
