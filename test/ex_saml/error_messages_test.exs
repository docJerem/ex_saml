defmodule ExSaml.ErrorMessagesTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExSaml.{Core.StatusCode, Error, ErrorMessages}

  setup do
    Logger.metadata(ex_saml_saml_sub_status: nil)
    :ok
  end

  @unknown_en "An unknown SAML error occurred."

  test "every catalogued code has an English and a French message" do
    for code <- ErrorMessages.codes() do
      en = ErrorMessages.get(code, "en")
      fr = ErrorMessages.get(code, "fr")

      assert is_binary(en) and en != Atom.to_string(code), "missing en message for #{code}"
      assert is_binary(fr) and fr != Atom.to_string(code), "missing fr message for #{code}"

      if code != :unknown_error,
        do: refute(en == @unknown_en, "#{code} falls back to unknown_error")
    end
  end

  test "every reason produced on the sign-in path has a dedicated message" do
    reasons = [
      :bad_saml,
      :bad_assertion,
      :bad_version,
      :bad_recipient,
      :bad_audience,
      :too_early,
      :stale_assertion,
      :duplicate,
      :missing_saml_response,
      :idp_initiated_not_allowed,
      :invalid_target_url,
      :invalid_relay_state,
      :invalid_idp_id,
      {:invalid_response, "boom"},
      {:unknown_idp, "x"},
      {:exception, "boom"},
      {:envelope, {:error, :no_signature}},
      {:envelope, {:error, :bad_digest}},
      {:assertion, {:error, :no_signature}},
      {:assertion, {:error, :bad_signature}},
      {:assertion, {:error, :cert_not_accepted}},
      {:assertion, {:error, :missing_certificate}},
      {:envelope, {:error, :missing_certificate}},
      {:assertion, {:error, :multiple_signatures}},
      {:assertion, {:error, :insecure_algorithm}},
      {:assertion, {:error, :unsupported_algorithm}},
      {:error, :bad_audience},
      [assertion: :not_found],
      :unauthorized
    ]

    for reason <- reasons do
      message = ErrorMessages.get(reason)
      assert is_binary(message)
      refute message == @unknown_en, "#{inspect(reason)} falls back to unknown_error"
    end
  end

  test "unknown codes no longer raise: generic message plus a warning" do
    log =
      capture_log(fn ->
        assert ErrorMessages.get(:something_new) == @unknown_en
        assert ErrorMessages.get({:weird, 1, 2, 3}) == @unknown_en
      end)

    assert log =~ "No error message for code :something_new"
  end

  describe "{:saml_error, status, message}" do
    @responder ~c"urn:oasis:names:tc:SAML:2.0:status:Responder"
    @requester ~c"urn:oasis:names:tc:SAML:2.0:status:Requester"

    test "top-level fallbacks" do
      assert ErrorMessages.get({:saml_error, @responder, nil}) ==
               ErrorMessages.get(:status_responder)

      assert ErrorMessages.get({:saml_error, @requester, nil}) ==
               ErrorMessages.get(:invalid_nameid_policy)
    end

    test "prefers the nested status recorded by Core.Sp" do
      Logger.metadata(ex_saml_saml_sub_status: :authn_failed)
      assert ErrorMessages.get({:saml_error, @responder, nil}) =~ "AuthnFailed"
    end

    test "every second-level status has a message" do
      for status <- StatusCode.second_level() do
        message = ErrorMessages.get(status)
        assert is_binary(message)
        refute message == @unknown_en, "#{status} falls back to unknown_error"
      end

      # `:invalid_nameid_policy` is both a legacy code and a spec status; the
      # legacy message wins for the bare atom, the spec one for nested statuses.
      Logger.metadata(ex_saml_saml_sub_status: :invalid_nameid_policy)
      assert ErrorMessages.get({:saml_error, @requester, nil}) =~ "InvalidNameIDPolicy"
    end
  end

  test "accepts %ExSaml.Error{} and uses its nested status when present" do
    error = %Error{reason: {:saml_error, @responder, nil}, saml_sub_status: :unknown_principal}
    assert ErrorMessages.get(error) =~ "UnknownPrincipal"

    error = %Error{reason: :bad_audience}
    assert ErrorMessages.get(error) == ErrorMessages.get(:bad_audience)
    assert ErrorMessages.get(error, "fr") == ErrorMessages.get(:bad_audience, "fr")
  end
end
