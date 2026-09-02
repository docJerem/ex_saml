defmodule ExSaml.AssertionTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{
    Assertion,
    AssertionCache,
    AuthorizationCodeCache,
    Debug,
    Error,
    StubCache,
    Subject
  }

  setup do
    StubCache.install()
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_idp_id: nil, ex_saml_debug_id: nil)
    :ok
  end

  describe "get_from_code/1" do
    test "returns the attributes when code and assertion are present, single use" do
      key = {"acme", "user@example.com"}

      assertion = %Assertion{
        idp_id: "acme",
        subject: %Subject{name: "user@example.com"},
        attributes: %{"email" => "user@example.com"}
      }

      AssertionCache.put(key, assertion, ttl: :timer.minutes(1))
      AuthorizationCodeCache.put_new!("c1", key)

      assert {:ok, {"acme", %{"email" => "user@example.com"}}} = Assertion.get_from_code("c1")

      assert {:error, %Error{reason: :authorization_code_not_found, step: :code_exchange}} =
               Assertion.get_from_code("c1")
    end

    test "distinguishes a missing code from a missing assertion, and traces both in debug" do
      Debug.enable()
      Debug.link_code("c2", "flow-2", "acme")
      AuthorizationCodeCache.put_new!("c2", {"acme", "ghost"})

      log =
        capture_log(fn ->
          assert {:error,
                  %Error{reason: :assertion_not_found, step: :code_exchange, idp_id: "acme"}} =
                   Assertion.get_from_code("c2")

          assert {:error, %Error{reason: :authorization_code_not_found}} =
                   Assertion.get_from_code("c2")
        end)

      assert log =~ "[ExSaml.Debug] code_exchanged"
      assert log =~ "Authorization code not found or expired"

      exchanged = for {:code_exchanged, meta} <- Debug.report("flow-2"), do: meta

      assert [%{assertion_found: false, assertion_key: {"acme", "ghost"}}, %{code_found: false}] =
               exchanged
    end

    test "legacy shape is still reachable through Error.to_legacy/1" do
      {:error, error} = Assertion.get_from_code("nope")
      assert Error.to_legacy(error) == :unauthorized
    end
  end
end
