defmodule ExSaml.AuthorizationCodeCacheTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{AuthorizationCodeCache, Debug, StubCache}

  setup do
    StubCache.install()
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_trace_id: nil)
    :ok
  end

  test "put_new!/take hit, then miss — silent when debug is off" do
    log =
      capture_log(fn ->
        assert :ok =
                 AuthorizationCodeCache.put_new!("c1", %{ex_saml_assertion_key: {"acme", "u"}})

        assert %{ex_saml_assertion_key: {"acme", "u"}} = AuthorizationCodeCache.take("c1")
        assert AuthorizationCodeCache.take("c1") == nil
      end)

    refute log =~ "[ExSaml.Debug]"
    assert Debug.failures("acme") == []
  end

  test "codes linked to a flow are traced under the same trace_id, per-IdP scope, and a missed take promotes the capture" do
    Debug.enable(idp_id: "acme")
    Debug.link_code("c2", "flow-1", "acme")

    Debug.stash_capture("acme", "flow-1", %{
      saml_response: "PHNhbWw+",
      relay_state: "flow-1",
      received_at: DateTime.utc_now()
    })

    log =
      capture_log(fn ->
        AuthorizationCodeCache.put_new!("c2", %{ex_saml_assertion_key: {"acme", "u"}})
        assert %{} = AuthorizationCodeCache.take("c2")
        assert AuthorizationCodeCache.take("c2") == nil
      end)

    assert log =~ "[ExSaml.Debug] code_stored"
    assert log =~ "[ExSaml.Debug] code_taken"

    assert [
             {:code_stored, %{code: "c2", put_new: true, ttl: ttl}},
             {:code_taken, %{code: "c2", hit: true, remaining_ttl: remaining}},
             {:code_taken, %{code: "c2", hit: false, value: nil}}
           ] = Debug.trace("flow-1")

    assert ttl == AuthorizationCodeCache.ttl()
    assert remaining == ttl

    # The second take (already used code) promoted the provisional capture:
    # the SAMLResponse that led to it is kept and the flow is listed as failed.
    assert %{
             captured_on: :authorization_code_not_found,
             saml_response: "PHNhbWw+",
             error: %{reason: :authorization_code_not_found, step: :code_exchange}
           } = Debug.failure("flow-1")

    assert [%{trace_id: "flow-1"}] = Debug.failures("acme")
  end

  test "codes minted by consumers (not linked) are only traced under the global flag" do
    Debug.enable(idp_id: "acme")

    log = capture_log(fn -> AuthorizationCodeCache.put("c3", %{idp_id: "acme"}) end)
    refute log =~ "[ExSaml.Debug]"

    Debug.enable()
    log = capture_log(fn -> assert %{idp_id: "acme"} = AuthorizationCodeCache.take("c3") end)
    assert log =~ "[ExSaml.Debug] code_taken"
    # The code is a bearer credential: never in the logs in :steps mode.
    assert log =~ "code: :redacted"
    refute log =~ ~s(code: "c3")
  end
end
