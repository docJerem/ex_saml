defmodule ExSaml.DebugRouterTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias ExSaml.Core.SpConfig
  alias ExSaml.Debug
  alias ExSaml.DebugRouter
  alias ExSaml.IdpData
  alias ExSaml.StubCache

  @payload %{
    saml_response: Base.encode64("<samlp:Response/>"),
    saml_encoding: nil,
    relay_state: "rs-1",
    consume_uri: "https://sp.example.com/consume",
    entity_id: "https://sp.example.com/metadata",
    received_at: ~U[2026-09-02 10:00:00Z]
  }

  setup do
    StubCache.install()
    previous_idps = Application.get_env(:ex_saml, :identity_providers)
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Application.delete_env(:ex_saml, :debug_cache)
    Process.delete(:ex_saml_debug_capture)
    Process.put(:authz, {:ok, ["acme"]})
    Process.put(:actor, "svc:test")

    Application.put_env(:ex_saml, :identity_providers, %{
      "acme" => %IdpData{
        id: "acme",
        sp_config: %SpConfig{
          metadata_uri: "https://sp.example.com/metadata",
          consume_uri: "https://sp.example.com/consume",
          idp_signs_envelopes: false,
          idp_signs_assertions: false
        }
      }
    })

    on_exit(fn ->
      Application.delete_env(:ex_saml, :debug_runtime)
      Application.delete_env(:ex_saml, :debug_cache)

      if previous_idps,
        do: Application.put_env(:ex_saml, :identity_providers, previous_idps),
        else: Application.delete_env(:ex_saml, :identity_providers)
    end)

    :ok
  end

  # Driven through the process dictionary so each test can vary them.
  def authorize(_conn) do
    case Process.get(:authz) do
      :raise -> raise "boom"
      other -> other
    end
  end

  def actor(_conn), do: Process.get(:actor)

  defp opts(extra \\ []) do
    Keyword.merge(
      [authorize: {__MODULE__, :authorize}, actor: {__MODULE__, :actor}],
      extra
    )
  end

  defp call(method, path, body \\ nil, extra \\ []) do
    conn = conn(method, path, body)
    conn = if body, do: put_req_header(conn, "content-type", "application/json"), else: conn

    # The flag memo lives in the process dictionary for a second, and every
    # request here runs in the test process; under a real server each request
    # is its own process and never sees a stale one.
    Debug.invalidate_memo()

    DebugRouter.call(conn, DebugRouter.init(opts(extra)))
  end

  defp json(conn), do: Jason.decode!(conn.resp_body)
  defp error_code(conn), do: json(conn)["error"]["code"]

  defp capture_failure(idp_id \\ "acme", trace_id \\ "t1") do
    Debug.enable(idp_id: idp_id, capture: :always, log: :silent)
    Debug.invalidate_memo()
    Debug.stash_capture(idp_id, trace_id, @payload)

    Debug.promote(trace_id, %{
      reason: :bad_digest,
      scope: :assertion,
      step: :decode,
      idp_id: idp_id
    })

    trace_id
  end

  describe "init/1" do
    test "refuses to start without an access rule" do
      # This router reads authentication data; there is no safe default.
      assert_raise ArgumentError, ~r/requires an :authorize option/, fn ->
        DebugRouter.init([])
      end
    end

    test "accepts an explicit decision to have none" do
      assert DebugRouter.init(authorize: :none)
    end

    test "rejects unknown options at mount time, not on the first request" do
      assert_raise ArgumentError, ~r/unknown/, fn ->
        DebugRouter.init(authorize: :none, allow_everything: true)
      end
    end
  end

  describe "GET /debug" do
    test "reports the switch, the retention config and the cache" do
      conn = call(:get, "/debug")

      assert conn.status == 200
      # A scoped caller is shown its own IdP whether or not debug is on for it.
      assert %{
               "global" => %{"enabled" => false},
               "idps" => [%{"idp_id" => "acme", "enabled" => false}],
               "degraded" => false
             } = json(conn)

      assert json(conn)["config"]["trace_ttl_ms"] == 900_000
      assert json(conn)["cache"] == %{"configured" => true}
    end

    test "a scoped caller sees only its own IdPs" do
      Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))
      Debug.enable(idp_id: "other", ttl: :timer.minutes(30))

      assert [%{"idp_id" => "acme", "enabled" => true}] = json(call(:get, "/debug"))["idps"]
    end

    test "an unrestricted caller sees every flagged IdP" do
      Process.put(:authz, {:ok, :all})
      Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))
      Debug.enable(idp_id: "other", ttl: :timer.minutes(30))

      ids = json(call(:get, "/debug"))["idps"] |> Enum.map(& &1["idp_id"]) |> Enum.sort()

      assert ids == ["acme", "other"]
    end

    test "a failing cache is reported, not raised" do
      Application.put_env(:ex_saml, :debug_cache, ExSaml.RaisingCache)
      Process.put(:authz, {:ok, :all})

      conn = call(:get, "/debug")

      assert conn.status == 200
      assert json(conn)["degraded"] == true
    end

    test "says so when no cache is configured" do
      Application.delete_env(:ex_saml, :cache)

      conn = call(:get, "/debug")

      assert conn.status == 200
      assert json(conn)["cache"] == %{"configured" => false}
      assert get_resp_header(conn, "x-ex-saml-cache") == ["none"]
    end
  end

  describe "PUT /debug/idps/:idp_id" do
    test "enables the IdP and reports when it expires" do
      conn =
        call(:put, "/debug/idps/acme", ~s({"ttl_ms":1800000,"capture":"always","log":"silent"}))

      assert conn.status == 200

      assert %{
               "scope" => "idp",
               "idp_id" => "acme",
               "enabled" => true,
               "settings" => %{"capture" => "always", "log" => "silent"},
               "expires_in_ms" => ttl
             } = json(conn)

      assert ttl > 1_700_000

      Debug.invalidate_memo()
      assert Debug.enabled?("acme")
    end

    test "accepts a request with no body" do
      assert call(:put, "/debug/idps/acme").status == 200
    end

    test "refuses a capture mode outside the catalogue" do
      conn = call(:put, "/debug/idps/acme", ~s({"capture":"sometimes"}))

      assert conn.status == 400
      assert error_code(conn) == "invalid_parameter"
      assert json(conn)["error"]["allowed"] == ["always", "none", "on_error"]
    end

    test "refuses a ttl above the mount's cap" do
      conn = call(:put, "/debug/idps/acme", ~s({"ttl_ms":999999999}))

      assert conn.status == 400
      assert error_code(conn) == "ttl_too_large"
      assert json(conn)["error"]["max_ms"] == 4 * 60 * 60 * 1000
    end

    test "refuses a non-numeric ttl" do
      assert error_code(call(:put, "/debug/idps/acme", ~s({"ttl_ms":"soon"}))) ==
               "invalid_parameter"
    end
  end

  describe "DELETE /debug/idps/:idp_id" do
    test "disables and answers no content" do
      Debug.enable(idp_id: "acme")

      conn = call(:delete, "/debug/idps/acme")

      assert conn.status == 204
      assert conn.resp_body == ""

      Debug.invalidate_memo()
      refute Debug.enabled?("acme")
    end
  end

  describe "the global switch" do
    test "is refused on a scoped mount" do
      assert error_code(call(:put, "/debug")) == "global_scope_forbidden"
      assert error_code(call(:delete, "/debug")) == "global_scope_forbidden"
    end

    test "is refused for a scoped caller even when the mount allows it" do
      assert error_code(call(:put, "/debug", nil, allow_global_scope: true)) ==
               "global_scope_forbidden"
    end

    test "works for an unrestricted caller on a mount that allows it" do
      Process.put(:authz, {:ok, :all})

      conn = call(:put, "/debug", ~s({"ttl_ms":60000}), allow_global_scope: true)

      assert conn.status == 200
      assert json(conn)["scope"] == "global"
      assert json(conn)["idp_id"] == nil
    end
  end

  describe "GET /idps/:idp_id/failures" do
    test "lists them, most recent first" do
      capture_failure("acme", "t1")

      conn = call(:get, "/idps/acme/failures")

      assert conn.status == 200
      assert %{"idp_id" => "acme", "count" => 1, "failures" => [failure]} = json(conn)
      assert failure["trace_id"] == "t1"
      assert failure["error"]["reason"] == "bad_digest"
      assert failure["captured_on"] == "error"
    end

    test "an IdP with no failures is an empty list, not a 404" do
      assert %{"count" => 0, "failures" => []} = json(call(:get, "/idps/acme/failures"))
    end

    test "an IdP that does not exist says so" do
      Process.put(:authz, {:ok, ["ghost"]})

      assert error_code(call(:get, "/idps/ghost/failures")) == "unknown_idp"
    end
  end

  describe "GET /failures/:trace_id" do
    test "describes the failure and points at the payload" do
      capture_failure()

      conn = call(:get, "/failures/t1")

      assert conn.status == 200
      body = json(conn)

      assert body["idp_id"] == "acme"
      assert body["error"]["reason"] == "bad_digest"
      assert body["relay_state"] == "rs-1"
      assert body["saml_response"]["present"] == true
      assert body["saml_response"]["href"] == "/failures/t1/saml_response"
      assert is_binary(body["message"])
      assert body["locale"] == "en"
    end

    test "translates the message" do
      capture_failure()

      assert json(call(:get, "/failures/t1?locale=fr"))["locale"] == "fr"

      refute json(call(:get, "/failures/t1?locale=fr"))["message"] ==
               json(call(:get, "/failures/t1"))["message"]
    end

    test "refuses a locale the library does not ship" do
      capture_failure()

      assert error_code(call(:get, "/failures/t1?locale=de")) == "invalid_locale"
    end

    test "an unknown trace is not found" do
      assert error_code(call(:get, "/failures/nope")) == "capture_not_found"
    end

    test "the href follows the mount prefix" do
      capture_failure()

      conn =
        :get
        |> conn("/failures/t1")
        |> Map.put(:script_name, ["admin", "saml"])
        |> DebugRouter.call(DebugRouter.init(opts()))

      assert json(conn)["saml_response"]["href"] == "/admin/saml/failures/t1/saml_response"
    end
  end

  describe "GET /failures/:trace_id/saml_response" do
    test "returns the base64 exactly as it was posted" do
      capture_failure()

      conn = call(:get, "/failures/t1/saml_response")

      assert conn.status == 200
      assert json(conn)["base64"] == @payload.saml_response
    end

    test "returns the decoded document as an attachment" do
      capture_failure()

      conn = call(:get, "/failures/t1/saml_response?format=xml")

      assert conn.status == 200
      assert conn.resp_body == "<samlp:Response/>"

      assert get_resp_header(conn, "content-disposition") == [
               ~s(attachment; filename="saml-response-t1.xml")
             ]
    end

    test "Accept selects the format, and ?format= overrides it" do
      capture_failure()

      xml =
        :get
        |> conn("/failures/t1/saml_response")
        |> put_req_header("accept", "application/xml")
        |> DebugRouter.call(DebugRouter.init(opts()))

      assert xml.resp_body == "<samlp:Response/>"

      json_wins =
        :get
        |> conn("/failures/t1/saml_response?format=json")
        |> put_req_header("accept", "application/xml")
        |> DebugRouter.call(DebugRouter.init(opts()))

      assert Jason.decode!(json_wins.resp_body)["base64"] == @payload.saml_response
    end

    test "refuses an unknown format" do
      capture_failure()

      assert error_code(call(:get, "/failures/t1/saml_response?format=yaml")) == "invalid_format"
    end

    test "says when the flow was captured without its payload" do
      Debug.enable(idp_id: "acme", capture: :none, log: :silent)
      Debug.invalidate_memo()
      Debug.stash_capture("acme", "t2", @payload)
      Debug.promote("t2", %{reason: :bad_digest, step: :decode, idp_id: "acme"})

      assert error_code(call(:get, "/failures/t2/saml_response")) == "payload_not_captured"
    end

    test "a payload that cannot be decoded is distinct from one that is missing" do
      Debug.enable(idp_id: "acme", capture: :always, log: :silent)
      Debug.invalidate_memo()
      Debug.stash_capture("acme", "t3", %{@payload | saml_response: "!!!not-base64!!!"})
      Debug.promote("t3", %{reason: :bad_digest, step: :decode, idp_id: "acme"})

      conn = call(:get, "/failures/t3/saml_response?format=xml")

      assert conn.status == 409
      assert error_code(conn) == "payload_not_decodable"
    end

    test "can be turned off at the mount" do
      capture_failure()

      assert error_code(
               call(:get, "/failures/t1/saml_response", nil, allow_payload_download: false)
             ) ==
               "payload_download_forbidden"
    end
  end

  describe "POST /failures/:trace_id/replay" do
    test "a response that still fails is a result, not an error" do
      capture_failure()

      conn = call(:post, "/failures/t1/replay")

      # The ordinary answer to "is it fixed yet?".
      assert conn.status == 200
      assert json(conn)["result"] == "error"
      assert json(conn)["error"]["step"] == "decode"
      assert json(conn)["evaluated_at"] == "2026-09-02T10:00:00Z"
    end

    test "an unknown trace is not found" do
      assert error_code(call(:post, "/failures/nope/replay")) == "capture_not_found"
    end

    test "refuses a malformed instant" do
      capture_failure()

      assert error_code(call(:post, "/failures/t1/replay", ~s({"now":"soon"}))) ==
               "invalid_parameter"
    end

    test "evaluates at the given instant" do
      capture_failure()

      conn = call(:post, "/failures/t1/replay", ~s({"now":"2026-09-03T12:14:03Z"}))

      assert json(conn)["evaluated_at"] == "2026-09-03T12:14:03Z"
    end
  end

  describe "GET /traces/:trace_id" do
    setup do
      Debug.enable(idp_id: "acme", log: :silent)
      Debug.invalidate_memo()

      capture_log(fn ->
        Debug.log(:code_issued, "acme", %{
          trace_id: "tr1",
          code: "live-credential",
          name_id: "jane@corp.com"
        })
      end)

      :ok
    end

    test "is redacted by default" do
      conn = call(:get, "/traces/tr1")

      assert conn.status == 200
      assert %{"redacted" => true, "count" => 1, "events" => [event]} = json(conn)
      assert event["event"] == "code_issued"
      assert event["idp_id"] == "acme"
      assert event["data"]["code"] == "redacted"
      assert event["data"]["name_id"] == "j***@corp.com"

      # Lifted out of data, and the trace id is not repeated per event.
      assert is_binary(event["at"])
      refute Map.has_key?(event["data"], "at")
      refute Map.has_key?(event["data"], "trace_id")
    end

    test "unredacted access is refused by default" do
      # An unredacted trace carries the authorization code, which is live.
      assert error_code(call(:get, "/traces/tr1?redact=false")) == "unredacted_forbidden"
    end

    test "unredacted access is possible when the mount allows it" do
      conn = call(:get, "/traces/tr1?redact=false", nil, allow_unredacted: true)

      assert json(conn)["redacted"] == false
      assert json(conn)["events"] |> hd() |> get_in(["data", "code"]) == "live-credential"
    end

    test "an unknown trace is not found" do
      assert error_code(call(:get, "/traces/nope")) == "trace_not_found"
    end
  end

  describe "tenancy" do
    test "an IdP outside the caller's set is refused" do
      assert error_code(call(:get, "/idps/other/failures")) == "forbidden_idp"
      assert error_code(call(:put, "/debug/idps/other")) == "forbidden_idp"
      assert error_code(call(:delete, "/debug/idps/other")) == "forbidden_idp"
    end

    test "another tenant's trace is not found, not forbidden" do
      # Trace ids travel — they are the ?error_id= a user pastes into a ticket —
      # so a 403 here would be a free existence oracle.
      capture_failure("other", "t-other")

      assert error_code(call(:get, "/failures/t-other")) == "capture_not_found"
      assert error_code(call(:post, "/failures/t-other/replay")) == "capture_not_found"
    end

    test "a capture that cannot be attributed is invisible to a scoped caller" do
      # A flow that failed before IdP lookup has no IdP to attribute it to, so
      # it takes the global flag to record one at all.
      Debug.enable(capture: :always, log: :silent)
      Debug.invalidate_memo()
      Debug.stash_capture(nil, "t-orphan", @payload)

      assert error_code(call(:get, "/failures/t-orphan")) == "capture_not_found"

      Process.put(:authz, {:ok, :all})
      assert call(:get, "/failures/t-orphan").status == 200
    end
  end

  describe "access control" do
    test "an unauthenticated caller is told so" do
      Process.put(:authz, {:error, :unauthenticated})

      conn = call(:get, "/debug")

      assert conn.status == 401
      assert error_code(conn) == "unauthenticated"
    end

    test "a refused caller is not told why" do
      Process.put(:authz, {:error, :wrong_tenant_for_reasons})

      conn = call(:get, "/debug")

      assert conn.status == 403
      assert error_code(conn) == "forbidden"
      refute conn.resp_body =~ "wrong_tenant"
    end

    test "a request with no actor is refused by default" do
      Process.put(:actor, nil)

      assert error_code(call(:get, "/debug")) == "actor_required"
    end

    test "an actor can be made optional" do
      Process.put(:actor, nil)

      assert call(:get, "/debug", nil, require_actor: false).status == 200
    end
  end

  describe "identifiers" do
    test "are validated before they reach a header or the cache" do
      conn = call(:get, "/failures/a%0D%0AX-Injected:%201/saml_response")

      assert conn.status == 400
      assert error_code(conn) == "invalid_identifier"
      assert get_resp_header(conn, "content-disposition") == []
    end

    test "reject path traversal" do
      assert error_code(call(:get, "/idps/..%2F..%2Fetc/failures")) == "invalid_identifier"
    end
  end

  describe "writes with no cache configured" do
    setup do
      Application.delete_env(:ex_saml, :cache)
      :ok
    end

    test "are refused rather than arming a single node" do
      conn = call(:put, "/debug/idps/acme")

      assert conn.status == 409
      assert error_code(conn) == "cache_not_configured"
    end

    test "are allowed when the mount says it is single-node" do
      assert call(:put, "/debug/idps/acme", nil, allow_node_local: true).status == 200
    end

    test "reads still answer, and say the cache is missing" do
      conn = call(:get, "/idps/acme/failures")

      assert conn.status == 200
      assert get_resp_header(conn, "x-ex-saml-cache") == ["none"]
    end
  end

  describe "GET /validation" do
    test "lists the enforced and the available checks" do
      conn = call(:get, "/validation")

      assert conn.status == 200
      assert "bad_issuer" in json(conn)["enforced"]
      assert "duplicate" in json(conn)["available"]
      assert json(conn)["mutable"] == false
    end
  end

  describe "an unexpected error" do
    test "still sends the envelope, and is re-raised for the host's reporter" do
      Process.put(:authz, :raise)

      log =
        capture_log(fn ->
          assert_raise RuntimeError, "boom", fn -> call(:get, "/debug") end
        end)

      # `handle_errors` receives the conn as it was before the pipeline ran, so
      # the audit callback registered inside it is not on that conn: a crash is
      # logged at :error instead of producing an audit line.
      assert log =~ "unhandled error"
      assert log =~ "boom"
    end
  end

  describe "the envelope" do
    test "is the same shape everywhere, and echoes the identifiers" do
      conn = call(:get, "/failures/nope")

      assert %{"error" => %{"code" => _, "message" => _, "trace_id" => "nope"}} = json(conn)
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
    end

    test "an unknown route is a 404 in the same shape" do
      conn = call(:get, "/nothing/here")

      assert conn.status == 404
      assert error_code(conn) == "not_found"
    end
  end

  describe "auditing" do
    test "logs one line per request, naming the actor" do
      log = capture_log(fn -> call(:get, "/debug") end)

      assert log =~ "[ExSaml.DebugRouter] GET /debug"
      assert log =~ "actor=svc:test"
      assert log =~ "status=200"
      assert log =~ "pii=false"
    end

    test "logs refusals too" do
      Process.put(:authz, {:error, :nope})

      assert capture_log(fn -> call(:get, "/debug") end) =~ "status=403"
    end

    test "marks a payload download as personal data" do
      capture_failure()

      log = capture_log(fn -> call(:get, "/failures/t1/saml_response?format=xml") end)

      assert log =~ "pii=true"
      assert log =~ "trace_id=t1"
    end

    test "does not mark a download that handed over nothing" do
      Debug.enable(idp_id: "acme", capture: :always, log: :silent)
      Debug.invalidate_memo()
      Debug.stash_capture("acme", "t-bad", %{@payload | saml_response: "!!!not-base64!!!"})
      Debug.promote("t-bad", %{reason: :bad_digest, step: :decode, idp_id: "acme"})

      log = capture_log(fn -> call(:get, "/failures/t-bad/saml_response?format=xml") end)

      assert log =~ "status=409"
      assert log =~ "pii=false"
    end

    test "reports to a configured sink as well as the log" do
      test = self()
      Process.put(:sink, test)

      call(:get, "/debug", nil, audit_sink: {__MODULE__, :sink})

      assert_receive {:audit, %{method: "GET", actor: "svc:test", status: 200}}
    end

    test "a sink that raises does not break the response" do
      assert call(:get, "/debug", nil, audit_sink: {__MODULE__, :raising_sink}).status == 200
    end

    test "marks an unredacted trace as personal data" do
      Debug.enable(idp_id: "acme", log: :silent)
      Debug.invalidate_memo()
      Debug.log(:code_issued, "acme", %{trace_id: "tr2", code: "c"})

      log =
        capture_log(fn -> call(:get, "/traces/tr2?redact=false", nil, allow_unredacted: true) end)

      assert log =~ "pii=true"
    end
  end

  def sink(entry) do
    send(Process.get(:sink), {:audit, entry})
    :ok
  end

  def raising_sink(_entry), do: raise("sink is down")
end
