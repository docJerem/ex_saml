defmodule ExSaml.Debug.ViewTest do
  use ExUnit.Case, async: false

  alias ExSaml.Core.Assertion, as: CoreAssertion
  alias ExSaml.Core.Subject
  alias ExSaml.Debug.View
  alias ExSaml.Error
  alias ExSaml.StubCache

  setup do
    StubCache.install()
    :ok
  end

  describe "debug_all/1" do
    test "reads the scope-keyed maps status/0 actually returns" do
      status = %{
        global: false,
        static: false,
        idps: ["acme"],
        settings: %{
          :global => nil,
          {:idp, "acme"} => %{capture: :on_error, log: :steps}
        },
        expires_in_ms: %{{:idp, "acme"} => 1_799_812}
      }

      assert %{
               "global" => %{"enabled" => false, "settings" => nil, "expires_in_ms" => nil},
               "static" => false,
               "idps" => [
                 %{
                   "idp_id" => "acme",
                   "enabled" => true,
                   "effective_settings" => %{"capture" => "on_error", "log" => "steps"},
                   "expires_in_ms" => 1_799_812
                 }
               ],
               "degraded" => false
             } = View.debug_all(status)
    end

    test "an IdP called \"global\" does not collide with the global scope" do
      # The reason `idps` is an array of objects rather than an object keyed by
      # name: `idp_id` is consumer-chosen free text.
      status = %{
        global: true,
        static: false,
        idps: ["global"],
        settings: %{
          :global => %{capture: :always, log: :full},
          {:idp, "global"} => %{capture: :none, log: :silent}
        },
        expires_in_ms: %{:global => 10, {:idp, "global"} => 20}
      }

      rendered = View.debug_all(status)

      assert rendered["global"]["settings"] == %{"capture" => "always", "log" => "full"}
      assert rendered["global"]["expires_in_ms"] == 10

      assert [%{"idp_id" => "global", "effective_settings" => %{"capture" => "none"}}] =
               rendered["idps"]
    end

    test "renders the rescue shape as degraded rather than crashing" do
      # status/0 returns this smaller map when the cache raises: no :settings,
      # no :expires_in_ms.
      status = %{global: false, static: false, idps: [], error: "%RuntimeError{}"}

      assert %{"degraded" => true, "idps" => [], "global" => %{"enabled" => false}} =
               View.debug_all(status)
    end

    test "reports the retention config and whether a cache is configured" do
      assert %{
               "config" => %{
                 "trace_ttl_ms" => 900_000,
                 "payload_ttl_ms" => 3_600_000,
                 "max_failures_per_idp" => 20,
                 "enforced_response_checks" => checks
               },
               "cache" => %{"configured" => true}
             } = View.debug_all(%{global: false, static: false, idps: []})

      assert "bad_issuer" in checks
    end
  end

  describe "debug_scoped/2" do
    test "reports only the caller's scopes and hides the global settings" do
      scopes = [
        {"acme",
         %{
           enabled: true,
           static: false,
           settings: %{capture: :always, log: :silent},
           expires_in_ms: 500
         }}
      ]

      rendered = View.debug_scoped(true, scopes)

      # Enough to explain traces they did not enable, without the settings.
      assert rendered["global"] == %{"enabled" => true}

      assert [%{"idp_id" => "acme", "enabled" => true, "expires_in_ms" => 500}] = rendered["idps"]
    end
  end

  describe "failure/3" do
    test "summarises the payload instead of inlining it" do
      capture = %{
        trace_id: "t1",
        idp_id: "acme",
        received_at: ~U[2026-09-03 12:14:03Z],
        captured_on: :error,
        error: %{reason: :bad_digest, scope: :assertion, step: :decode, idp_id: "acme"},
        saml_response: String.duplicate("A", 6120)
      }

      rendered = View.failure(capture, "en", "/failures/t1/saml_response")

      assert rendered["saml_response"] == %{
               "present" => true,
               "bytes" => 6120,
               "href" => "/failures/t1/saml_response"
             }

      assert rendered["received_at"] == "2026-09-03T12:14:03Z"
      assert rendered["captured_on"] == "error"
      assert rendered["error"]["reason"] == "bad_digest"
      assert is_binary(rendered["message"])
    end

    test "tolerates the keys a Map.take-built capture simply does not have" do
      capture = %{trace_id: "t2", idp_id: "acme", captured_on: :pending}

      rendered = View.failure(capture, "en", "/failures/t2/saml_response")

      assert rendered["received_at"] == nil
      assert rendered["relay_state"] == nil
      assert rendered["saml_response"] == %{"present" => false, "bytes" => nil, "href" => nil}
      assert rendered["message"] == nil
    end

    test "translates the message" do
      capture = %{trace_id: "t3", error: %{reason: :cert_not_accepted}}

      en = View.failure(capture, "en", "/x")["message"]
      fr = View.failure(capture, "fr", "/x")["message"]

      assert is_binary(en) and is_binary(fr)
      refute en == fr
    end
  end

  describe "trace/3" do
    test "lifts the stamped fields out of the event data" do
      events = [
        {:validation_check,
         %{
           at: ~U[2026-09-03 12:14:03Z],
           node: :"app@10.0.0.7",
           trace_id: "t1",
           idp_id: "acme",
           check: :bad_issuer,
           enforced: false
         }}
      ]

      assert %{
               "trace_id" => "t1",
               "redacted" => true,
               "count" => 1,
               "events" => [event]
             } = View.trace("t1", events, true)

      assert event["event"] == "validation_check"
      assert event["at"] == "2026-09-03T12:14:03Z"
      assert event["node"] == "app@10.0.0.7"
      assert event["idp_id"] == "acme"

      # Lifted, not duplicated; and trace_id is not repeated per event.
      assert event["data"] == %{"check" => "bad_issuer", "enforced" => false}
    end
  end

  describe "replay" do
    test "summarises a successful assertion without returning it whole" do
      assertion = %CoreAssertion{
        issuer: ~c"https://idp.example.com",
        recipient: ~c"https://sp.example.com/consume",
        subject: %Subject{name: "jane@corp.com"},
        attributes: [email: ~c"jane@corp.com", groups: [~c"admins"]]
      }

      assert %{
               "result" => "ok",
               "assertion" => %{
                 "issuer" => "https://idp.example.com",
                 "subject" => "j***@corp.com",
                 "attributes" => ["email", "groups"]
               }
             } = View.replay_ok("t1", ~U[2026-09-03 12:14:03Z], assertion)
    end

    test "a response that still fails is a result, not an error of the call" do
      error = %Error{reason: :cert_not_accepted, scope: :assertion, step: :decode, idp_id: "acme"}

      assert %{
               "result" => "error",
               "error" => %{
                 "reason" => "cert_not_accepted",
                 "scope" => "assertion",
                 "step" => "decode"
               }
             } = View.replay_error("t1", ~U[2026-09-03 12:14:03Z], error)
    end
  end

  describe "validation/0 and error/3" do
    test "lists the enforced and available checks" do
      assert %{"enforced" => enforced, "available" => available, "mutable" => false} =
               View.validation()

      assert "bad_issuer" in enforced
      assert "duplicate" in available
    end

    test "the error envelope carries a code and any extras" do
      assert View.error(:capture_not_found, "No capture.", %{"trace_id" => "t1"}) == %{
               "error" => %{
                 "code" => "capture_not_found",
                 "message" => "No capture.",
                 "trace_id" => "t1"
               }
             }
    end
  end
end
