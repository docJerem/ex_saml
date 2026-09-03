defmodule ExSaml.DebugTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{Core.SpConfig, Debug, Error, IdpData, StubCache}

  setup do
    StubCache.install()
    previous_static = Application.get_env(:ex_saml, :debug)
    previous_idps = Application.get_env(:ex_saml, :identity_providers)
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Application.delete_env(:ex_saml, :debug_cache)
    Application.delete_env(:ex_saml, :debug_log_level)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_trace_id: nil)
    Process.delete(:ex_saml_debug_capture)

    on_exit(fn ->
      Application.delete_env(:ex_saml, :debug_runtime)
      Application.delete_env(:ex_saml, :debug_cache)
      Application.delete_env(:ex_saml, :debug_log_level)
      Application.delete_env(:ex_saml, :max_failures_per_idp)
      Application.delete_env(:ex_saml, :payload_ttl)
      Application.delete_env(:ex_saml, :provisional_ttl)

      if is_nil(previous_static),
        do: Application.delete_env(:ex_saml, :debug),
        else: Application.put_env(:ex_saml, :debug, previous_static)

      if is_nil(previous_idps),
        do: Application.delete_env(:ex_saml, :identity_providers),
        else: Application.put_env(:ex_saml, :identity_providers, previous_idps)
    end)

    :ok
  end

  @payload %{
    saml_response: Base.encode64("<not-saml/>"),
    saml_encoding: nil,
    relay_state: "rs-1",
    consume_uri: "https://sp.example.com/consume",
    entity_id: "https://sp.example.com/metadata",
    received_at: ~U[2026-09-02 10:00:00Z]
  }

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
      assert :ok = Debug.stash_capture("acme", "t", @payload)
      assert :ok = Debug.promote("t", %{reason: :bad_saml, step: :decode})
      assert Debug.failures("acme") == []
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

    test "a dedicated debug cache is used for flags, traces and captures" do
      Application.put_env(:ex_saml, :debug_cache, ExSaml.StubCache)
      Application.put_env(:ex_saml, :cache, ExSaml.RaisingCache)

      assert {:ok, _} = Debug.enable(idp_id: "acme", capture: :always)
      assert Debug.enabled?("acme")

      capture_log(fn -> Debug.log(:event, %{idp_id: "acme", trace_id: "t1"}) end)
      assert [{:event, _}] = Debug.trace("t1")

      Debug.stash_capture("acme", "t1", @payload)
      assert %{captured_on: :always} = Debug.capture("t1")
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

  describe "log/2,3 and trace/1" do
    test "log/2 is a no-op when disabled" do
      log =
        capture_log(fn -> assert :ok = Debug.log(:event, %{idp_id: "acme", trace_id: "t1"}) end)

      assert log == ""
      assert Debug.trace("t1") == nil
    end

    test "writes a warning with the metadata and appends to the trace, in order" do
      Debug.enable(idp_id: "acme")

      log =
        capture_log(fn ->
          Debug.log(:first, %{idp_id: "acme", trace_id: "t1", foo: 1})
          Debug.log(:second, "acme", fn -> %{trace_id: "t1", bar: 2} end)
        end)

      assert log =~ "[ExSaml.Debug] first"
      assert log =~ "foo: 1"
      assert log =~ "[ExSaml.Debug] second"
      assert log =~ "bar: 2"

      assert [{:first, first}, {:second, second}] = Debug.trace("t1")
      assert first.foo == 1
      assert first.node == node()
      assert %DateTime{} = first.at
      assert second.bar == 2
    end

    test "log: :steps redacts PII from the log message but not from the trace" do
      Debug.enable(idp_id: "acme")

      log =
        capture_log(fn ->
          Debug.log(:response_received, %{
            idp_id: "acme",
            trace_id: "t1",
            saml_response: "PHNhbWw+",
            assertion_key: {"acme", "user@example.com"},
            host: "sp.example.com"
          })
        end)

      assert log =~ "saml_response: :redacted"
      assert log =~ ~s(assertion_key: {"acme", "u***@example.com"})
      refute log =~ "user@example.com"
      assert log =~ ~s(host: "sp.example.com")

      assert [
               {:response_received,
                %{saml_response: "PHNhbWw+", assertion_key: {"acme", "user@example.com"}}}
             ] = Debug.trace("t1")
    end

    # Review points 5 and 6: credentials are fully redacted, NameIDs partially
    # masked (recognisable, not disclosed), and nested containers follow the
    # same rules.
    test "redact/1 rules: credentials, name ids, nested containers" do
      redacted =
        Debug.redact(%{
          code: "abc123",
          nonce: "n1",
          saml_nonce: "n2",
          assertion_key: {"acme", "jane@corp.com"},
          value: %{
            ex_saml_assertion_key: {"acme", "employee-42"},
            saml_nonce_candidate: "n3",
            trace_id: "t1"
          },
          payload: %{ex_saml_assertion_key: {"acme", "jane@corp.com"}},
          cache_value: {"acme", "jane@corp.com"},
          relay_cache_entry: %{saml_nonce: "n4", user_token: "tok", target_url: "/cb"},
          assertion: %{attributes: %{}},
          trace_id: "t1",
          empty: nil
        })

      assert redacted.code == :redacted
      assert redacted.nonce == :redacted
      assert redacted.saml_nonce == :redacted
      assert redacted.assertion_key == {"acme", "j***@corp.com"}

      assert redacted.value == %{
               ex_saml_assertion_key: {"acme", "em***(11)"},
               saml_nonce_candidate: :redacted,
               trace_id: "t1"
             }

      assert redacted.payload == %{ex_saml_assertion_key: {"acme", "j***@corp.com"}}
      assert redacted.cache_value == {"acme", "j***@corp.com"}

      assert redacted.relay_cache_entry == %{
               saml_nonce: :redacted,
               user_token: :redacted,
               target_url: "/cb"
             }

      assert redacted.assertion == :redacted
      assert redacted.trace_id == "t1"
      assert redacted.empty == nil
    end

    test "log: :full keeps everything in the log message" do
      Debug.enable(idp_id: "acme", log: :full)

      log =
        capture_log(fn ->
          Debug.log(:response_received, %{
            idp_id: "acme",
            trace_id: "t1",
            saml_response: "PHNhbWw+"
          })
        end)

      assert log =~ ~s(saml_response: "PHNhbWw+")
    end

    test "log: :silent writes nothing but still feeds the trace" do
      Debug.enable(idp_id: "acme", log: :silent)

      log = capture_log(fn -> Debug.log(:event, %{idp_id: "acme", trace_id: "t1"}) end)

      assert log == ""
      assert [{:event, _}] = Debug.trace("t1")
    end

    test "log level is configurable" do
      Application.put_env(:ex_saml, :debug_log_level, :info)
      Debug.enable(idp_id: "acme")

      log = capture_log(fn -> Debug.log(:event, %{idp_id: "acme"}) end)
      assert log =~ "[info]"
    end

    test "lazy metadata is not evaluated when disabled" do
      Debug.log(:event, fn -> flunk("should not be evaluated") end)
    end

    test "uses the process context when the metadata carries no idp_id / trace_id" do
      Debug.enable(idp_id: "acme")
      Debug.put_context("acme", "ctx-id")

      capture_log(fn -> Debug.log(:event, %{value: 42}) end)

      assert [{:event, %{value: 42, idp_id: "acme", trace_id: "ctx-id"}}] = Debug.trace("ctx-id")
    end

    test "record/3 ignores empty trace ids" do
      assert :ok = Debug.record("", :event, %{})
      assert :ok = Debug.record(nil, :event, %{})
    end
  end

  describe "captures" do
    test "capture: :on_error writes a provisional capture, promoted on failure" do
      Application.put_env(:ex_saml, :provisional_ttl, 1111)
      Application.put_env(:ex_saml, :payload_ttl, 2222)
      Debug.enable(idp_id: "acme")

      assert :ok = Debug.stash_capture("acme", "t1", @payload)

      assert %{
               captured_on: :pending,
               error: nil,
               saml_response: payload,
               consume_uri: "https://sp.example.com/consume"
             } =
               Debug.capture("t1")

      assert payload == @payload.saml_response
      assert StubCache.ttl({ExSaml.Debug, {:capture, "t1"}}) == 1111
      assert Debug.failure("t1") == nil
      assert Debug.failures("acme") == []

      error =
        Error.from_reason({:envelope, {:error, :bad_digest}},
          step: :decode,
          idp_id: "acme",
          trace_id: "t1"
        )

      assert :ok = Debug.promote("t1", error)

      assert %{
               captured_on: :error,
               error: %{reason: :bad_digest, scope: :envelope, step: :decode}
             } =
               Debug.failure("t1")

      assert StubCache.ttl({ExSaml.Debug, {:capture, "t1"}}) == 2222

      assert [
               %{
                 trace_id: "t1",
                 captured_on: :error,
                 error: %{reason: :bad_digest},
                 received_at: ~U[2026-09-02 10:00:00Z]
               }
             ] =
               Debug.failures("acme")
    end

    # Review point 9: the provisional capture must outlive the whole code
    # exchange window (30 s code TTL + a late or retried consumer callback).
    test "the default provisional TTL is 5 minutes" do
      Debug.enable(idp_id: "acme")
      Debug.stash_capture("acme", "t1", @payload)
      assert StubCache.ttl({ExSaml.Debug, {:capture, "t1"}}) == :timer.minutes(5)
    end

    test "capture: :always persists immediately with the full TTL" do
      Application.put_env(:ex_saml, :payload_ttl, 3333)
      Debug.enable(idp_id: "acme", capture: :always)

      Debug.stash_capture("acme", "t1", @payload)
      assert %{captured_on: :always, error: nil} = Debug.capture("t1")
      assert StubCache.ttl({ExSaml.Debug, {:capture, "t1"}}) == 3333
    end

    test "capture: :none keeps a failure record without the payload" do
      Debug.enable(idp_id: "acme", capture: :none)

      Debug.stash_capture("acme", "t1", @payload)
      assert Debug.capture("t1") == nil

      Debug.promote("t1", %{reason: :bad_saml, step: :decode, idp_id: "acme"})

      assert %{saml_response: nil, error: %{reason: :bad_saml}, relay_state: "rs-1"} =
               Debug.failure("t1")

      assert Debug.saml_response("t1") == nil
      assert [%{trace_id: "t1"}] = Debug.failures("acme")
    end

    test "promotion from another process (code exchange) builds a minimal record when needed" do
      Debug.enable(idp_id: "acme")

      Debug.promote(
        "t9",
        %{reason: :authorization_code_not_found, step: :code_exchange, idp_id: "acme"},
        :authorization_code_not_found
      )

      assert %{
               captured_on: :authorization_code_not_found,
               saml_response: nil,
               error: %{reason: :authorization_code_not_found}
             } =
               Debug.failure("t9")
    end

    test "nothing is recorded when debug is off" do
      Debug.stash_capture("acme", "t1", @payload)
      Debug.promote("t1", %{reason: :bad_saml, step: :decode, idp_id: "acme"})
      assert Debug.capture("t1") == nil
      assert Debug.failures("acme") == []
    end

    test "saml_response/2 returns the raw base64 or the decoded document" do
      Debug.enable(idp_id: "acme", capture: :always)
      Debug.stash_capture("acme", "t1", @payload)

      assert Debug.saml_response("t1") == @payload.saml_response
      assert Debug.saml_response("t1", decode: true) == "<not-saml/>"
      assert Debug.saml_response("nope") == nil
    end

    test "failures are listed most recent first and capped per IdP, evicting old captures" do
      Application.put_env(:ex_saml, :max_failures_per_idp, 2)
      Debug.enable(idp_id: "acme")

      for id <- ["t1", "t2", "t3"] do
        Debug.stash_capture("acme", id, @payload)
        Debug.promote(id, %{reason: :bad_saml, step: :decode, idp_id: "acme"})
      end

      assert ["t3", "t2"] = Enum.map(Debug.failures("acme"), & &1.trace_id)
      assert Debug.capture("t1") == nil
      assert Debug.failures("globex") == []
    end
  end

  describe "replay/2" do
    setup do
      idp = %IdpData{
        id: "acme",
        sp_config: %SpConfig{
          metadata_uri: "https://sp.example.com/metadata",
          consume_uri: "https://sp.example.com/consume",
          idp_signs_envelopes: false,
          idp_signs_assertions: false
        }
      }

      Application.put_env(:ex_saml, :identity_providers, %{"acme" => idp})
      Debug.enable(idp_id: "acme", capture: :always, log: :silent)
      :ok
    end

    test "replays the captured payload against the current IdP configuration" do
      Debug.stash_capture("acme", "t1", @payload)

      assert {:error, %Error{reason: :bad_saml, step: :decode, trace_id: "t1", idp_id: "acme"}} =
               Debug.replay("t1")
    end

    test "unknown trace, missing payload, unknown IdP" do
      assert {:error, %Error{reason: :capture_not_found, step: :replay, trace_id: "nope"}} =
               Debug.replay("nope")

      Debug.enable(idp_id: "acme", capture: :none)
      Debug.stash_capture("acme", "t2", @payload)
      Debug.promote("t2", %{reason: :bad_saml, step: :decode, idp_id: "acme"})
      assert {:error, %Error{reason: :payload_not_captured, step: :replay}} = Debug.replay("t2")

      Debug.enable(idp_id: "ghost", capture: :always)
      Debug.stash_capture("ghost", "t3", @payload)

      assert {:error, %Error{reason: :unknown_idp, idp_id: "ghost", step: :replay}} =
               Debug.replay("t3")
    end
  end

  # Review point 8: the debug machinery must cost nothing when debug is off.
  describe "cost when debug is off" do
    alias ExSaml.CountingCache

    test "scope checks and code lookups do not touch the cache beyond one memoised marker read" do
      CountingCache.install()

      for _ <- 1..5 do
        refute Debug.enabled?("acme")
        refute Debug.enabled?()
        assert Debug.log(:event, %{idp_id: "acme", trace_id: "t"}) == :ok
        assert Debug.log(:event, "acme", fn -> flunk("not evaluated") end) == :ok
        assert Debug.stash_capture("acme", "t", @payload) == :ok
        assert Debug.code_context("code") == nil
      end

      assert CountingCache.debug_reads() == 1
      assert [{:get, {ExSaml.Debug, :active}}] = CountingCache.calls()
    end

    test "enable/1 sets the active marker with the longest TTL and invalidates the memo" do
      CountingCache.install()
      refute Debug.enabled?("acme")

      Debug.enable(idp_id: "acme", ttl: :timer.minutes(10))
      assert Debug.enabled?("acme")
      assert StubCache.ttl({ExSaml.Debug, :active}) == :timer.minutes(10)

      Debug.enable(ttl: :timer.minutes(2))
      assert StubCache.ttl({ExSaml.Debug, :active}) == :timer.minutes(10)

      Debug.disable("acme")
      Debug.disable()
      refute Debug.enabled?("acme")
    end

    test "flag reads are memoised per process while debug is on" do
      CountingCache.install()
      Debug.enable(idp_id: "acme")
      CountingCache.reset()

      for _ <- 1..10, do: assert(Debug.enabled?("acme"))

      # one marker read + one pair of flag reads (idp, then global fallback is
      # not needed since the idp flag exists)
      assert CountingCache.debug_reads() <= 3
    end

    test "static and runtime overrides never touch the cache" do
      CountingCache.install()
      Application.put_env(:ex_saml, :debug, true)
      assert Debug.enabled?("acme")
      assert CountingCache.debug_reads() == 0
    end
  end

  describe "code correlation" do
    test "link_code/3 and code_context/1" do
      assert Debug.code_context("code-1") == nil

      # Links are only written (and read) while debug is active.
      Debug.enable(idp_id: "acme")
      Debug.link_code("code-1", "t1", "acme")
      assert Debug.code_context("code-1") == %{trace_id: "t1", idp_id: "acme"}

      Debug.link_code("code-2", nil, "acme")
      assert Debug.code_context("code-2") == nil
    end
  end
end
