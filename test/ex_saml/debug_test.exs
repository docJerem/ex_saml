defmodule ExSaml.DebugTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{Debug, StubCache}

  setup do
    StubCache.install()
    previous_static = Application.get_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_debug_id: nil)

    on_exit(fn ->
      Application.delete_env(:ex_saml, :debug_runtime)

      if is_nil(previous_static),
        do: Application.delete_env(:ex_saml, :debug),
        else: Application.put_env(:ex_saml, :debug, previous_static)
    end)

    :ok
  end

  describe "enabled?/1" do
    test "is false by default" do
      refute Debug.enabled?()
      refute Debug.enabled?("acme")
    end

    test "global enable/disable at runtime, without touching the config or restarting" do
      refute Debug.enabled?()

      assert {:ok, %{scope: :global, expires_at: %DateTime{}}} =
               Debug.enable(ttl: :timer.minutes(5))

      assert Debug.enabled?()
      assert Debug.enabled?("acme")
      assert Application.get_env(:ex_saml, :debug) == nil

      assert :ok = Debug.disable()
      refute Debug.enabled?()
    end

    test "per-idp enable does not leak to other IdPs" do
      assert {:ok, %{scope: {:idp, "acme"}}} = Debug.enable(idp_id: "acme")

      assert Debug.enabled?("acme")
      refute Debug.enabled?("globex")
      refute Debug.enabled?()

      Debug.disable("acme")
      refute Debug.enabled?("acme")
    end

    test "static config override" do
      Application.put_env(:ex_saml, :debug, true)
      assert Debug.enabled?()
      assert Debug.enabled?("anyone")
    end

    test "a raising cache yields false, never an exception" do
      Application.put_env(:ex_saml, :cache, ExSaml.RaisingCache)
      refute Debug.enabled?()
      refute Debug.enabled?("acme")
      assert :ok = Debug.log(:anything, %{idp_id: "acme"})
    end

    test "no cache configured yields false" do
      Application.delete_env(:ex_saml, :cache)
      refute Debug.enabled?()
    end

    test "falls back to a node-local runtime toggle when no cache is configured" do
      Application.delete_env(:ex_saml, :cache)

      assert {:ok, %{scope: :global}} = Debug.enable(ttl: :timer.minutes(5))
      assert Debug.enabled?()

      # Simulate the TTL elapsing: the stored expiry is in the past.
      past = DateTime.add(DateTime.utc_now(), -1, :second)
      Application.put_env(:ex_saml, :debug_runtime, %{global: past})
      refute Debug.enabled?()
    end
  end

  describe "status/0" do
    test "reports the global flag and the per-idp flags" do
      assert %{global: false, idps: []} = Debug.status()

      Debug.enable(idp_id: "acme", ttl: :timer.minutes(10))

      assert %{global: false, idps: ["acme"], expires_in_ms: %{{:idp, "acme"} => ttl}} =
               Debug.status()

      assert ttl == :timer.minutes(10)

      Debug.enable(ttl: :timer.minutes(1))
      assert %{global: true} = Debug.status()
    end
  end

  describe "log/2, capture/3 and report/1" do
    test "log/2 is a no-op when disabled" do
      log =
        capture_log(fn -> assert :ok = Debug.log(:step, %{idp_id: "acme", debug_id: "d1"}) end)

      assert log == ""
      assert Debug.report("d1") == nil
    end

    test "log/2 writes a warning with the metadata and appends to the report, in order" do
      Debug.enable(idp_id: "acme")

      log =
        capture_log(fn ->
          Debug.log(:first, %{idp_id: "acme", debug_id: "d1", foo: 1})
          Debug.log(:second, "acme", fn -> %{debug_id: "d1", bar: 2} end)
        end)

      assert log =~ "[ExSaml.Debug] first"
      assert log =~ "foo: 1"
      assert log =~ "[ExSaml.Debug] second"
      assert log =~ "bar: 2"

      assert [{:first, first}, {:second, second}] = Debug.report("d1")
      assert first.foo == 1
      assert first.node == node()
      assert %DateTime{} = first.at
      assert second.bar == 2
    end

    test "lazy metadata is not evaluated when disabled" do
      Debug.log(:step, fn -> flunk("should not be evaluated") end)
    end

    test "uses the process context when the metadata carries no idp_id / debug_id" do
      Debug.enable(idp_id: "acme")
      Debug.put_context("acme", "ctx-id")

      capture_log(fn -> Debug.log(:step, %{value: 42}) end)

      assert [{:step, %{value: 42, idp_id: "acme", debug_id: "ctx-id"}}] = Debug.report("ctx-id")
    end

    test "capture/3 ignores empty debug ids" do
      assert :ok = Debug.capture("", :step, %{})
      assert :ok = Debug.capture(nil, :step, %{})
    end
  end

  describe "link_code/3 and code_context/1" do
    test "links a code to its flow and IdP" do
      assert Debug.code_context("code-1") == nil

      Debug.link_code("code-1", "d1", "acme")
      assert Debug.code_context("code-1") == %{debug_id: "d1", idp_id: "acme"}
    end

    test "no link without a debug id" do
      Debug.link_code("code-2", nil, "acme")
      assert Debug.code_context("code-2") == nil
    end
  end
end
