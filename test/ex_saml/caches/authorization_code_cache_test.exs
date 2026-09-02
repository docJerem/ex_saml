defmodule ExSaml.AuthorizationCodeCacheTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{AuthorizationCodeCache, Debug, StubCache}

  setup do
    StubCache.install()
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_debug_id: nil)
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
  end

  test "codes linked to a flow are traced under the same debug_id, per-IdP scope" do
    Debug.enable(idp_id: "acme")
    Debug.link_code("c2", "flow-1", "acme")

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
           ] = Debug.report("flow-1")

    assert ttl == AuthorizationCodeCache.ttl()
    assert remaining == ttl
  end

  test "codes minted by consumers (not linked) are only traced under the global flag" do
    Debug.enable(idp_id: "acme")

    log = capture_log(fn -> AuthorizationCodeCache.put("c3", %{idp_id: "acme"}) end)
    refute log =~ "[ExSaml.Debug]"

    Debug.enable()
    log = capture_log(fn -> assert %{idp_id: "acme"} = AuthorizationCodeCache.take("c3") end)
    assert log =~ "[ExSaml.Debug] code_taken"
    assert log =~ ~s(code: "c3")
  end
end
