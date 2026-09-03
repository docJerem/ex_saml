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

    # InResponseTo (Profiles §4.1.4.3), from #55.
    test "returns {:ok, ...} when InResponseTo matches the AuthnRequest we issued" do
      idp = %IdpData{id: "idp-1"}

      conn =
        build_conn(%{
          "relay_state" => "rs-abc",
          "idp_id" => "idp-1",
          "saml_nonce" => "nonce-xyz",
          "authn_request_id" => "request-id-42"
        })

      assert {:ok, :sp_initiated, "nonce-xyz"} =
               SPHandler.validate_authresp(conn, idp, sp_initiated_assertion(), "rs-abc")
    end

    test "returns :bad_in_response_to when InResponseTo names a different request" do
      idp = %IdpData{id: "idp-1"}

      conn =
        build_conn(%{
          "relay_state" => "rs-abc",
          "idp_id" => "idp-1",
          "saml_nonce" => "nonce-xyz",
          "authn_request_id" => "some-other-request"
        })

      assert {:error, :bad_in_response_to} =
               SPHandler.validate_authresp(conn, idp, sp_initiated_assertion(), "rs-abc")
    end

    test "a mismatching InResponseTo only warns when the check is not enforced" do
      Application.put_env(:ex_saml, :enforced_response_checks, [])
      on_exit(fn -> Application.delete_env(:ex_saml, :enforced_response_checks) end)
      idp = %IdpData{id: "idp-1"}

      conn =
        build_conn(%{
          "relay_state" => "rs-abc",
          "idp_id" => "idp-1",
          "authn_request_id" => "some-other-request"
        })

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert {:ok, :sp_initiated, nil} =
                   SPHandler.validate_authresp(conn, idp, sp_initiated_assertion(), "rs-abc")
        end)

      assert log =~ "saml_validation check=:bad_in_response_to enforced=false"
      assert log =~ ~s(idp_id="idp-1")
      assert log =~ ~s(actual="request-id-42")
    end

    # Rolling-deploy regression: relay-state entries written before this check
    # existed carry no id, and every login in flight at deploy time would fail
    # if a missing id rejected instead of skipping.
    test "a stored nil AuthnRequest id skips the check instead of rejecting" do
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

    test "reads the AuthnRequest id from the relay-state cache when the session is empty" do
      idp = %IdpData{id: "idp-1"}

      Process.put(:stub_relay_cache_value, %{
        relay_state: "rs-abc",
        idp_id: "idp-1",
        saml_nonce: "nonce-xyz",
        authn_request_id: "request-id-42"
      })

      assert {:ok, :sp_initiated, "nonce-xyz"} =
               SPHandler.validate_authresp(
                 build_conn(%{}),
                 idp,
                 sp_initiated_assertion(),
                 "rs-abc"
               )

      Process.put(:stub_relay_cache_value, %{
        relay_state: "rs-abc",
        idp_id: "idp-1",
        saml_nonce: "nonce-xyz",
        authn_request_id: "wrong-request"
      })

      assert {:error, :bad_in_response_to} =
               SPHandler.validate_authresp(
                 build_conn(%{}),
                 idp,
                 sp_initiated_assertion(),
                 "rs-abc"
               )
    end

    test "a bad relay state still reports :invalid_relay_state, not :bad_in_response_to" do
      idp = %IdpData{id: "idp-1"}

      conn =
        build_conn(%{
          "relay_state" => "rs-different",
          "idp_id" => "idp-1",
          "authn_request_id" => "some-other-request"
        })

      assert {:error, :invalid_relay_state} =
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
  # consume_signin_response/1 — failure path issues an error_id (= trace_id)
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

      assert {:error, %Error{reason: :unknown_idp, idp_id: "nope", trace: nil}} =
               get_session(conn, "ex_saml_error")

      assert {:ok,
              %Error{
                trace_id: ^error_id,
                reason: :unknown_idp,
                idp_id: "nope",
                step: :idp_lookup,
                trace: nil
              } = error} = Error.get_from_id(error_id)

      assert Error.to_legacy(error) == {:unknown_idp, "nope"}
      assert {:error, %Error{reason: :error_not_found}} = Error.get_from_id(error_id)
    end

    test "missing SAMLResponse -> :missing_saml_response with step :decode" do
      conn = SPHandler.consume_signin_response(acs_conn("idp-1", %{"RelayState" => "rs-1"}))

      {_location, error_id} = error_id_from(conn)

      assert {:ok,
              %Error{
                reason: :missing_saml_response,
                step: :decode,
                idp_id: "idp-1",
                relay_state: "rs-1",
                trace_id: ^error_id
              }} = Error.get_from_id(error_id)
    end

    test "the trace_id exists even when debug is off" do
      conn = SPHandler.consume_signin_response(acs_conn("idp-1"))
      {_, error_id} = error_id_from(conn)
      assert {:ok, %Error{trace_id: trace_id, trace: nil}} = Error.get_from_id(error_id)
      assert is_binary(trace_id) and trace_id == error_id
    end

    test "target_url from session gets the error_id appended, preserving its query" do
      conn =
        SPHandler.consume_signin_response(
          acs_conn("idp-1", %{}, %{"target_url" => "https://app.example.com/cb?x=1"})
        )

      {location, error_id} = error_id_from(conn)
      assert location == "https://app.example.com/cb?x=1&error_id=#{error_id}"
    end

    test "an exception while consuming fails closed with an error_id (never a bare 500)" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("broken", %{"SAMLResponse" => "x"}))
          assert conn.status == 302
          {_, error_id} = error_id_from(conn)

          assert {:ok, %Error{reason: :exception, step: :unexpected, detail: detail} = error} =
                   Error.get_from_id(error_id)

          assert detail =~ "ensure_sp_uris_set"
          assert Error.to_legacy(error) == {:exception, detail}
        end)

      assert log =~ "consume_signin_response crashed"
    end

    test "in debug mode the error carries the flow trace and the capture is promoted" do
      Debug.enable(idp_id: "idp-1")
      body = %{"SAMLResponse" => Base.encode64("<not-saml/>"), "RelayState" => "rs-2"}

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("idp-1", body))
          {_, error_id} = error_id_from(conn)

          assert {:ok, %Error{trace_id: trace_id, trace: trace, reason: :bad_saml}} =
                   Error.get_from_id(error_id)

          steps = Enum.map(trace, &elem(&1, 0))
          assert :response_received in steps
          assert :decode_result in steps

          # The trace keeps growing after the error was built (`:error_issued` is last).
          full = Debug.trace(trace_id)
          assert Enum.take(full, length(trace)) == trace
          assert {:error_issued, %{trace_id: ^trace_id}} = List.last(full)

          # The capture is promoted with the error summary and the raw payload.
          assert %{
                   captured_on: :error,
                   error: %{reason: :bad_saml, step: :decode},
                   saml_response: saml_response,
                   relay_state: "rs-2",
                   consume_uri: "https://sp.example.com/consume",
                   entity_id: "https://sp.example.com/metadata"
                 } = Debug.failure(trace_id)

          assert saml_response == body["SAMLResponse"]
          assert Debug.saml_response(trace_id, decode: true) == "<not-saml/>"
          assert [%{trace_id: ^trace_id}] = Debug.failures("idp-1")

          # Nothing but the size of the payload in the trace.
          refute inspect(trace, limit: :infinity, printable_limit: :infinity) =~
                   body["SAMLResponse"]

          assert {:response_received, %{saml_response_bytes: bytes}} =
                   List.keyfind(trace, :response_received, 0)

          assert bytes == byte_size(body["SAMLResponse"])
        end)

      assert log =~ "[ExSaml.Debug] response_received"
      assert log =~ "[ExSaml.Debug] error_issued"
      refute log =~ body["SAMLResponse"]
    end

    test "without debug nothing is logged, no trace, no capture" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("idp-1"))
          {_, error_id} = error_id_from(conn)
          assert {:ok, %Error{trace: nil, trace_id: trace_id}} = Error.get_from_id(error_id)
          assert Debug.failure(trace_id) == nil
        end)

      refute log =~ "[ExSaml.Debug]"
    end

    test "an undecodable payload is :invalid_response, with the exception in the trace" do
      Debug.enable(idp_id: "idp-1", log: :silent)

      conn =
        SPHandler.consume_signin_response(acs_conn("idp-1", %{"SAMLResponse" => "not base64!!"}))

      {_, error_id} = error_id_from(conn)

      assert {:ok, %Error{reason: :invalid_response, step: :decode, detail: detail, trace: trace}} =
               Error.get_from_id(error_id)

      # The exception class depends on the OTP release (:badarg wrapped one way
      # or another); what matters is that the cause is kept.
      assert is_binary(detail) and detail =~ "Error"

      assert {:decode_payload_failed, %{payload_bytes: 12, error: formatted}} =
               List.keyfind(trace, :decode_payload_failed, 0)

      assert formatted =~ "** ("
    end

    test "capture: :none leaves a failure record without the payload" do
      Debug.enable(idp_id: "idp-1", capture: :none, log: :silent)
      body = %{"SAMLResponse" => Base.encode64("<not-saml/>")}

      conn = SPHandler.consume_signin_response(acs_conn("idp-1", body))
      {_, error_id} = error_id_from(conn)
      {:ok, %Error{trace_id: trace_id}} = Error.get_from_id(error_id)

      assert %{saml_response: nil, error: %{reason: :bad_saml}} = Debug.failure(trace_id)
      assert Debug.saml_response(trace_id) == nil
    end

    # Review point 1: "back" + re-submit of the IdP form replays the same
    # RelayState, hence the same trace_id. The second failure must overwrite the
    # first, never raise on the error store.
    test "two failures under the same RelayState share the trace_id, the latest error wins" do
      session = %{"relay_state" => "rs-same", "idp_id" => "idp-1"}

      conn1 =
        SPHandler.consume_signin_response(
          acs_conn("idp-1", %{"RelayState" => "rs-same"}, session)
        )

      conn2 =
        SPHandler.consume_signin_response(
          acs_conn(
            "idp-1",
            %{"RelayState" => "rs-same", "SAMLResponse" => Base.encode64("<not-saml/>")},
            session
          )
        )

      assert conn1.status == 302 and conn2.status == 302
      {_, id1} = error_id_from(conn1)
      {_, id2} = error_id_from(conn2)
      assert id1 == "rs-same" and id2 == "rs-same"

      # Nobody consulted the first error: the second one replaced it.
      assert {:ok, %Error{reason: :bad_saml, trace_id: "rs-same"}} = Error.get_from_id("rs-same")
      assert {:error, %Error{reason: :error_not_found}} = Error.get_from_id("rs-same")
    end

    # Review point 2: Logger metadata is process-scoped and a Bandit connection
    # process serves requests sequentially, so a request must never inherit the
    # trace of the previous one, whatever step it fails at.
    test "a request served by the same process never inherits the previous flow's trace" do
      Debug.enable(idp_id: "idp-1", log: :silent)

      # Flow of user A fails inside the library, its trace and capture exist.
      conn_a =
        SPHandler.consume_signin_response(
          acs_conn(
            "idp-1",
            %{"SAMLResponse" => Base.encode64("<not-saml/>"), "RelayState" => "rs-A"},
            %{
              "relay_state" => "rs-A",
              "idp_id" => "idp-1"
            }
          )
        )

      {_, "rs-A"} = error_id_from(conn_a)
      assert Debug.trace("rs-A") != nil

      # The context is gone once the request is over.
      assert Debug.context() == {nil, nil}
      assert Logger.metadata()[:ex_saml_saml_sub_status] == nil
      assert Process.get(:ex_saml_debug_capture) == nil

      # User B, same process, fails before the IdP is even resolved.
      conn_b = SPHandler.consume_signin_response(acs_conn("nope"))
      {_, id_b} = error_id_from(conn_b)

      assert id_b != "rs-A"

      assert {:ok, %Error{trace_id: ^id_b, reason: :unknown_idp, trace: nil}} =
               Error.get_from_id(id_b)

      # A's diagnostic data is untouched.
      assert %{error: %{reason: :bad_saml}} = Debug.failure("rs-A")
      assert Enum.map(Debug.failures("idp-1"), & &1.trace_id) == ["rs-A"]

      # Same for a crash before the library clause.
      conn_c = SPHandler.consume_signin_response(acs_conn("broken", %{"SAMLResponse" => "x"}))
      {_, id_c} = error_id_from(conn_c)
      assert id_c != "rs-A"
      assert {:ok, %Error{reason: :exception, trace_id: ^id_c}} = Error.get_from_id(id_c)
    end

    test "consume_signin_response/2 used directly clears the process context too" do
      Debug.enable(idp_id: "idp-1", log: :silent)
      idp = Application.get_env(:ex_saml, :identity_providers)["idp-1"]

      assert {:error, %Error{reason: :missing_saml_response, trace_id: trace_id}} =
               SPHandler.consume_signin_response(acs_conn("idp-1"), idp)

      assert is_binary(trace_id)
      assert Debug.context() == {nil, nil}
    end

    # Review point 8: with debug off, a whole ACS request (failure path, which
    # exercises every instrumentation point) must not read the cache for the
    # debug machinery beyond the single memoised "active" marker.
    test "an ACS request with debug off performs a single debug-related cache read" do
      ExSaml.CountingCache.install()
      Debug.invalidate_memo()

      conn = SPHandler.consume_signin_response(acs_conn("idp-1", %{"RelayState" => "rs-9"}))
      assert conn.status == 302

      assert ExSaml.CountingCache.debug_reads() == 1

      debug_writes =
        Enum.count(ExSaml.CountingCache.calls(), fn {op, key} ->
          op in [:put, :put_new!] and match?({ExSaml.Debug, _}, key)
        end)

      assert debug_writes == 0
    end

    test "when even the error cannot be issued (cache down), the ACS fails closed with 403" do
      Application.put_env(:ex_saml, :cache, ExSaml.RaisingCache)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = SPHandler.consume_signin_response(acs_conn("idp-1"))
          assert conn.status == 403
          assert conn.resp_body == "access_denied"
          assert conn.halted
        end)

      assert log =~ "could not issue error_id"
    end
  end
end
