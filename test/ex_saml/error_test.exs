defmodule ExSaml.ErrorTest do
  use ExUnit.Case, async: false

  alias ExSaml.{Debug, Error, ErrorCache, StubCache}

  @responder ~c"urn:oasis:names:tc:SAML:2.0:status:Responder"

  setup do
    StubCache.install()
    Application.delete_env(:ex_saml, :debug)
    Application.delete_env(:ex_saml, :debug_runtime)
    Logger.metadata(ex_saml_saml_sub_status: nil, ex_saml_idp_id: nil, ex_saml_trace_id: nil)
    :ok
  end

  describe "from_reason/2 keeps everything the legacy tuples carried" do
    test "bare atom" do
      assert %Error{reason: :bad_audience, scope: nil, detail: nil} =
               Error.from_reason(:bad_audience)
    end

    test "{:error, reason} wrapper" do
      assert %Error{reason: :bad_recipient} = Error.from_reason({:error, :bad_recipient})
    end

    test "signature failures keep the element in :scope" do
      assert %Error{reason: :no_signature, scope: :envelope} =
               Error.from_reason({:envelope, {:error, :no_signature}})

      assert %Error{reason: :bad_digest, scope: :assertion} =
               Error.from_reason({:assertion, {:error, :bad_digest}})

      assert %Error{reason: :missing_certificate, scope: :assertion} =
               Error.from_reason({:assertion, {:error, :missing_certificate}})
    end

    test "IdP status keeps the raw URI, the atoms, the message and the nested status" do
      Logger.metadata(ex_saml_saml_sub_status: :authn_failed)

      error = Error.from_reason({:saml_error, @responder, ~c"User could not be authenticated"})

      assert %Error{
               reason: :saml_error,
               saml_status: :responder,
               saml_status_uri: "urn:oasis:names:tc:SAML:2.0:status:Responder",
               saml_sub_status: :authn_failed,
               saml_message: "User could not be authenticated",
               detail: nil
             } = error
    end

    test "IdP status with a malformed or missing message" do
      assert %Error{saml_message: nil, detail: "malformed StatusMessage"} =
               Error.from_reason({:saml_error, @responder, :malformed})

      assert %Error{saml_message: nil, detail: nil} =
               Error.from_reason({:saml_error, @responder, nil})
    end

    test "unknown status URI is kept verbatim" do
      error = Error.from_reason({:saml_error, "urn:example:custom", nil})
      assert error.saml_status == :unknown
      assert error.saml_status_uri == "urn:example:custom"
    end

    test "free-text reasons go to :detail" do
      assert %Error{reason: :invalid_response, detail: "%ArgumentError{}"} =
               Error.from_reason({:invalid_response, "%ArgumentError{}"})

      assert %Error{reason: :exception, detail: "boom"} = Error.from_reason({:exception, "boom"})
    end

    test "unknown idp keeps the id" do
      assert %Error{reason: :unknown_idp, idp_id: "nope"} =
               Error.from_reason({:unknown_idp, "nope"})
    end

    test "legacy get_from_code reasons" do
      assert %Error{reason: :assertion_not_found} = Error.from_reason(assertion: :not_found)
    end

    test "anything else becomes :unknown_error with the term in :detail" do
      assert %Error{reason: :unknown_error, detail: "{:weird, 1}"} =
               Error.from_reason({:weird, 1})

      assert %Error{reason: :unknown_error, detail: "nil"} = Error.from_reason(nil)
    end

    test "attrs are merged, node and timestamp are set" do
      error =
        Error.from_reason(:bad_audience,
          step: :decode,
          idp_id: "acme",
          relay_state: "rs",
          trace_id: "rs"
        )

      assert %Error{step: :decode, idp_id: "acme", relay_state: "rs", trace_id: "rs"} = error
      assert error.node == node()
      assert %DateTime{} = error.at
    end

    test "an existing struct is returned with attrs merged" do
      error = Error.from_reason(:bad_audience, step: :decode)

      assert %Error{reason: :bad_audience, step: :decode, flow: :sp_initiated} =
               Error.from_reason(error, flow: :sp_initiated)
    end
  end

  describe "to_legacy/1" do
    test "round-trips every legacy shape" do
      Logger.metadata(ex_saml_saml_sub_status: nil)

      for legacy <- [
            :bad_audience,
            {:envelope, {:error, :no_signature}},
            {:assertion, {:error, :bad_digest}},
            {:saml_error, @responder, ~c"denied"},
            {:saml_error, @responder, nil},
            {:invalid_response, "boom"},
            {:exception, "boom"},
            {:unknown_idp, "nope"},
            [assertion: :not_found]
          ] do
        assert legacy |> Error.from_reason() |> Error.to_legacy() == legacy
      end

      assert Error.to_legacy(%Error{reason: :authorization_code_not_found}) == :unauthorized
    end
  end

  describe "new/1" do
    test "leaves trace nil when debug is off" do
      assert %Error{trace: nil} =
               Error.new(%{reason: :bad_audience, idp_id: "acme", trace_id: "t1"})
    end

    test "embeds the debug trace when debug is on for the IdP" do
      Debug.enable(idp_id: "acme")
      Debug.record("t1", :authn_request, %{relay_state: "t1"})

      error = Error.new(%{reason: :invalid_relay_state, idp_id: "acme", trace_id: "t1"})

      assert [{:authn_request, %{relay_state: "t1"}}] = error.trace
    end
  end

  describe "issue/1 and get_from_id/1" do
    test "stores under the trace_id, single use" do
      error = Error.new(%{reason: :bad_recipient, step: :decode, trace_id: "t1"})
      assert %Error{trace_id: "t1"} = issued = Error.issue(error)

      assert ErrorCache.ttl("t1") == ErrorCache.ttl()

      assert {:ok, ^issued} = Error.get_from_id("t1")

      assert {:error, %Error{reason: :error_not_found, step: :error_lookup, detail: "t1"}} =
               Error.get_from_id("t1")
    end

    test "issuing twice under the same trace_id overwrites instead of raising" do
      Error.issue(Error.new(%{reason: :bad_recipient, trace_id: "rs-1"}))
      Error.issue(Error.new(%{reason: :bad_audience, trace_id: "rs-1"}))

      assert {:ok, %Error{reason: :bad_audience}} = Error.get_from_id("rs-1")
      assert {:error, %Error{reason: :error_not_found}} = Error.get_from_id("rs-1")
    end

    test "generates a trace_id when the error has none" do
      %Error{trace_id: trace_id} = Error.issue(Error.new(%{reason: :bad_recipient}))
      assert is_binary(trace_id)
      assert {:ok, %Error{trace_id: ^trace_id}} = Error.get_from_id(trace_id)
    end

    test "unknown or malformed ids" do
      assert {:error, %Error{reason: :error_not_found}} = Error.get_from_id("nope")
      assert {:error, %Error{reason: :error_not_found}} = Error.get_from_id(nil)
    end

    test "error_ttl config is honoured" do
      Application.put_env(:ex_saml, :error_ttl, 1234)
      on_exit(fn -> Application.delete_env(:ex_saml, :error_ttl) end)

      %Error{trace_id: trace_id} = Error.issue(Error.new(%{reason: :duplicate}))
      assert ErrorCache.ttl(trace_id) == 1234
    end
  end

  # Review point 4: the session copy must never push the cookie over 4 KB.
  describe "for_session/1" do
    test "drops the trace and caps the free-text fields at 512 bytes, keeping UTF-8 valid" do
      long = String.duplicate("é", 1000)

      error = %Error{
        reason: :exception,
        detail: long,
        saml_message: long,
        trace: [{:event, %{}}]
      }

      session = Error.for_session(error)

      assert session.trace == nil
      assert String.valid?(session.detail)
      assert byte_size(session.detail) <= 512 + byte_size("…")
      assert String.ends_with?(session.detail, "…")
      assert byte_size(session.saml_message) <= 512 + byte_size("…")

      short = %Error{reason: :bad_audience, detail: "short", saml_message: nil}
      assert Error.for_session(short) == %{short | trace: nil}
    end
  end

  describe "append_error_id/2" do
    test "adds the query param to a bare URL" do
      assert Error.append_error_id("https://app.example.com/callback", "abc") ==
               "https://app.example.com/callback?error_id=abc"
    end

    test "preserves an existing query string" do
      assert Error.append_error_id("/callback?foo=bar", "abc") == "/callback?foo=bar&error_id=abc"
    end
  end
end
