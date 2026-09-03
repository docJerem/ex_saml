defmodule ExSaml.RelayStateCacheTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{Debug, RelayStateCache, StubCache}

  setup do
    StubCache.install()
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_trace_id: nil)
    :ok
  end

  test "put / get / ttl / take / delete round-trip" do
    assert :ok = RelayStateCache.put("rs-1", %{idp_id: "acme"}, ttl: 1234)
    assert RelayStateCache.get("rs-1") == %{idp_id: "acme"}
    assert RelayStateCache.ttl("rs-1") == 1234

    assert RelayStateCache.take("rs-1") == %{idp_id: "acme"}
    assert RelayStateCache.take("rs-1") == nil

    RelayStateCache.put("rs-2", %{}, ttl: 1)
    assert :ok = RelayStateCache.delete("rs-2")
    assert RelayStateCache.get("rs-2") == nil
  end

  test "take/1 and delete/1 are silent when debug is off" do
    log =
      capture_log(fn ->
        RelayStateCache.put("rs-1", %{}, ttl: 1)
        RelayStateCache.take("rs-1")
        RelayStateCache.delete("rs-1")
      end)

    refute log =~ "[ExSaml.Debug]"
  end

  # The relay state is the trace_id of SP-initiated flows, so these events are
  # recorded under it (see #60 for the IdP-initiated attribution).
  test "take/1 and delete/1 are traced under the relay state when debug is on" do
    Debug.enable()
    RelayStateCache.put("rs-1", %{idp_id: "acme", saml_nonce: "n"}, ttl: 1)

    log =
      capture_log(fn ->
        assert %{idp_id: "acme"} = RelayStateCache.take("rs-1")
        assert RelayStateCache.take("rs-1") == nil
        RelayStateCache.delete("rs-1")
      end)

    assert log =~ "[ExSaml.Debug] relay_state_taken"
    # The cached entry holds a nonce: redacted (recursively) in :steps mode.
    assert log =~ "saml_nonce: :redacted"
    refute log =~ ~s(saml_nonce: "n")

    assert [
             {:relay_state_taken, %{hit: true, value: %{idp_id: "acme", saml_nonce: "n"}}},
             {:relay_state_taken, %{hit: false, value: nil}},
             {:relay_state_deleted, %{relay_state: "rs-1"}}
           ] = Debug.trace("rs-1")
  end
end
