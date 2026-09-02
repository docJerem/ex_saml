defmodule ExSaml.DebugTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{Debug, StubCache}

  setup do
    StubCache.install()
    previous_static = Application.get_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Application.delete_env(:ex_saml, :debug_cache)
    Application.delete_env(:ex_saml, :debug_log_level)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_debug_id: nil)
    Process.delete(:ex_saml_debug_payload)

    on_exit(fn ->
      Application.delete_env(:ex_saml, :debug_runtime)
      Application.delete_env(:ex_saml, :debug_cache)
      Application.delete_env(:ex_saml, :debug_log_level)

      if is_nil(previous_static),
        do: Application.delete_env(:ex_saml, :debug),
        else: Application.put_env(:ex_saml, :debug, previous_static)
    end)

    :ok
  end

  describe "enabled?/1 and settings/1" do
    test "is false by default" do
      refute Debug.enabled?()
      refute Debug.enabled?("acme")
      assert Debug.settings("acme") == nil
    end

    test "global enable/disable at runtime, without touching the config or restarting" do
      refute Debug.enabled?()

      assert {:ok, %{scope: :global, expires_at: %DateTime{}, settings: settings}} =
               Debug.enable(ttl: :timer.minutes(5))

      assert settings == %{capture: :on_error, log: :steps}
      assert Debug.enabled?()
      assert Debug.enabled?("acme")
      assert Application.get_env(:ex_saml, :debug) == nil

      assert :ok = Debug.disable()
      refute Debug.enabled?()
    end

    test "per-idp enable does not leak to other IdPs, and wins over the global flag" do
      assert {:ok, %{scope: {:idp, "acme"}}} = Debug.enable(idp_id: "acme", log: :silent)

      assert Debug.enabled?("acme")
      refute Debug.enabled?("globex")
      refute Debug.enabled?()

      Debug.enable(capture: :always, log: :full)
      assert Debug.settings("acme") == %{capture: :on_error, log: :silent}
      assert Debug.settings("globex") == %{capture: :always, log: :full}

      Debug.disable("acme")
      assert Debug.settings("acme") == %{capture: :always, log: :full}
    end

    test "options are validated" do
      assert_raise ArgumentError, fn -> Debug.enable(capture: :sometimes) end
      assert_raise ArgumentError, fn -> Debug.enable(log: :loud) end
    end

    test "static config override, boolean or keyword" do
      Application.put_env(:ex_saml, :debug, true)
      assert Debug.settings("anyone") == %{capture: :on_error, log: :steps}

      Application.put_env(:ex_saml, :debug, capture: :none, log: :full)
      assert Debug.settings() == %{capture: :none, log: :full}
    end

    test "a raising cache yields false, never an exception" do
      Application.put_env(:ex_saml, :cache, ExSaml.RaisingCache)
      refute Debug.enabled?()
      refute Debug.enabled?("acme")
      assert :ok = Debug.log(:anything, %{idp_id: "acme"})
      assert :ok = Debug.stash_payload("acme", "d", %{})
    end

    test "no cache configured yields false" do
      Application.delete_env(:ex_saml, :cache)
      refute Debug.enabled?()
    end

    test "falls back to a node-local runtime toggle when no cache is configured" do
      Application.delete_env(:ex_saml, :cache)

      assert {:ok, %{scope: :global}} = Debug.enable(ttl: :timer.minutes(5), log: :full)
      assert Debug.settings() == %{capture: :on_error, log: :full}

      # Simulate the TTL elapsing: the stored expiry is in the past.
      past = DateTime.add(DateTime.utc_now(), -1, :second)

      Application.put_env(:ex_saml, :debug_runtime, %{
        global: {%{capture: :on_error, log: :full}, past}
      })

      refute Debug.enabled?()
    end

    test "a dedicated debug cache is used for flags, reports and captures" do
      Application.put_env(:ex_saml, :debug_cache, ExSaml.StubCache)
      Application.put_env(:ex_saml, :cache, ExSaml.RaisingCache)

      assert {:ok, _} = Debug.enable(idp_id: "acme")
      assert Debug.enabled?("acme")

      capture_log(fn -> Debug.log(:step, %{idp_id: "acme", debug_id: "d1"}) end)
      assert [{:step, _}] = Debug.report("d1")
    end
  end

  describe "status/0" do
    test "reports the global flag, the per-idp flags, their settings and TTLs" do
      assert %{global: false, idps: []} = Debug.status()

      Debug.enable(idp_id: "acme", ttl: :timer.minutes(10), log: :silent)

      assert %{
               global: false,
               idps: ["acme"],
               settings: %{{:idp, "acme"} => %{log: :silent}},
               expires_in_ms: %{{:idp, "acme"} => ttl}
             } = Debug.status()

      assert ttl == :timer.minutes(10)

      Debug.enable(ttl: :timer.minutes(1))
      assert %{global: true} = Debug.status()
    end
  end

  describe "log/2,3 and report/1" do
    test "log/2 is a no-op when disabled" do
      log =
        capture_log(fn -> assert :ok = Debug.log(:step, %{idp_id: "acme", debug_id: "d1"}) end)

      assert log == ""
      assert Debug.report("d1") == nil
    end

    test "writes a warning with the metadata and appends to the report, in order" do
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

    test "log: :steps redacts PII from the log message but not from the report" do
      Debug.enable(idp_id: "acme")

      log =
        capture_log(fn ->
          Debug.log(:response_received, %{
            idp_id: "acme",
            debug_id: "d1",
            saml_response: "PHNhbWw+",
            assertion_key: {"acme", "user@example.com"},
            host: "sp.example.com"
          })
        end)

      assert log =~ "saml_response: :redacted"
      assert log =~ "assertion_key: :redacted"
      refute log =~ "user@example.com"
      assert log =~ ~s(host: "sp.example.com")

      assert [
               {:response_received,
                %{saml_response: "PHNhbWw+", assertion_key: {"acme", "user@example.com"}}}
             ] =
               Debug.report("d1")
    end

    test "log: :full keeps everything in the log message" do
      Debug.enable(idp_id: "acme", log: :full)

      log =
        capture_log(fn ->
          Debug.log(:response_received, %{
            idp_id: "acme",
            debug_id: "d1",
            saml_response: "PHNhbWw+"
          })
        end)

      assert log =~ ~s(saml_response: "PHNhbWw+")
    end

    test "log: :silent writes nothing but still feeds the report" do
      Debug.enable(idp_id: "acme", log: :silent)

      log = capture_log(fn -> Debug.log(:step, %{idp_id: "acme", debug_id: "d1"}) end)

      assert log == ""
      assert [{:step, _}] = Debug.report("d1")
    end

    test "log level is configurable" do
      Application.put_env(:ex_saml, :debug_log_level, :info)
      Debug.enable(idp_id: "acme")

      log = capture_log(fn -> Debug.log(:step, %{idp_id: "acme"}) end)
      assert log =~ "[info]"
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

  describe "SAMLResponse capture" do
    @payload %{saml_response: "PHNhbWw+", xml: "<saml>", relay_state: "d1"}

    test "capture: :on_error keeps the payload until the failure path persists it" do
      Debug.enable(idp_id: "acme")

      assert :ok = Debug.stash_payload("acme", "d1", @payload)
      assert Debug.saml_response("d1") == nil

      assert :ok = Debug.persist_payload("d1")
      assert %{saml_response: "PHNhbWw+", captured_on: :error} = Debug.saml_response("d1")

      # Nothing left to persist on a second call.
      assert :ok = Debug.persist_payload("d1")
    end

    test "capture: :always persists immediately" do
      Debug.enable(idp_id: "acme", capture: :always)

      Debug.stash_payload("acme", "d1", @payload)
      assert %{captured_on: :always} = Debug.saml_response("d1")
    end

    test "capture: :none never stores the payload" do
      Debug.enable(idp_id: "acme", capture: :none)

      Debug.stash_payload("acme", "d1", @payload)
      Debug.persist_payload("d1")
      assert Debug.saml_response("d1") == nil
    end

    test "nothing is stashed when debug is off" do
      Debug.stash_payload("acme", "d1", @payload)
      assert Process.get(:ex_saml_debug_payload) == nil
    end

    test "payload_ttl config is honoured" do
      Application.put_env(:ex_saml, :payload_ttl, 4321)
      on_exit(fn -> Application.delete_env(:ex_saml, :payload_ttl) end)
      Debug.enable(idp_id: "acme", capture: :always)

      Debug.stash_payload("acme", "d1", @payload)
      assert StubCache.ttl({ExSaml.Debug, {:payload, "d1"}}) == 4321
    end
  end

  describe "correlation indexes" do
    test "link_code/3 and code_context/1" do
      assert Debug.code_context("code-1") == nil

      Debug.link_code("code-1", "d1", "acme")
      assert Debug.code_context("code-1") == %{debug_id: "d1", idp_id: "acme"}

      Debug.link_code("code-2", nil, "acme")
      assert Debug.code_context("code-2") == nil
    end

    test "link_error/2 lets report/1 and saml_response/1 accept an error id" do
      Debug.enable(idp_id: "acme", capture: :always)
      Debug.capture("d1", :step, %{})
      Debug.stash_payload("acme", "d1", %{saml_response: "x"})

      Debug.link_error("err-1", "d1")

      assert [{:step, _}] = Debug.report("err-1")
      assert %{saml_response: "x"} = Debug.saml_response("err-1")
      assert Debug.report("unknown") == nil

      assert :ok = Debug.link_error("err-2", nil)
      assert Debug.report("err-2") == nil
    end
  end
end
