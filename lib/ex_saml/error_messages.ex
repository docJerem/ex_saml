defmodule ExSaml.ErrorMessages do
  @moduledoc """
  Error messages

  Provide a human-readable explanation for an error produced by the library.
  Accepts an `%ExSaml.Error{}`, a bare reason atom, or any legacy error term
  (`{:error, code}`, `{:envelope, {:error, :no_signature}}`,
  `{:saml_error, status, message}`, …): everything is normalised through
  `ExSaml.Error.from_reason/2` first.

  ## Example

      iex(2)> ExSaml.ErrorMessages.get(:bad_audience)
      "Make sure that the entity_id in configuration is correct"

      iex(3)> ExSaml.ErrorMessages.get(%ExSaml.Error{reason: :no_signature, scope: :assertion})
      "Missing signature. Please ensure that the assertions are properly signed."

  Unknown codes never raise: they yield the generic `unknown_error` message and
  are logged at `:warning` level so the raw code is not lost.
  """

  require Logger

  alias ExSaml.Core.StatusCode
  alias ExSaml.Error

  @signature_errors ~w(no_signature bad_digest bad_signature cert_not_accepted missing_certificate multiple_signatures insecure_algorithm unsupported_algorithm)a

  # Historical codes kept for compatibility with existing consumers.
  @legacy_errors ~w(assertion_cert_not_accepted missing_assertion_key cert_no_accepted invalid_nameid_policy invalid_nonce missing_assertion_signature missing_envelope_signature status_responder)a

  # Reasons produced by the library on the sign-in path.
  @flow_errors ~w(bad_saml bad_assertion bad_version bad_recipient bad_audience too_early stale_assertion duplicate invalid_response missing_saml_response idp_initiated_not_allowed invalid_target_url invalid_relay_state invalid_idp_id unknown_idp exception access_denied authorization_code_not_found assertion_not_found error_not_found unknown_error)a

  @errors Enum.uniq(@legacy_errors ++ @flow_errors ++ @signature_errors)

  # gettext msgids for second-level SAML statuses, e.g. `:saml_status_authn_failed`.
  # Built once at compile time from the closed catalogue, so no atom is ever
  # created from runtime input.
  @status_msgid_by_atom Map.new(StatusCode.second_level(), &{&1, :"saml_status_#{&1}"})
  @status_msgids Map.values(@status_msgid_by_atom)

  @doc "Every error code that has a dedicated message."
  @spec codes() :: [atom()]
  def codes, do: @errors ++ @status_msgids

  @doc "Returns the translated message for an error (struct, atom or legacy term)."
  @spec get(term(), String.t()) :: String.t()
  def get(error, locale \\ "en")

  def get(%Error{} = error, locale), do: message(error, locale)

  # Direct gettext ids (legacy codes, second-level status msgids) bypass the
  # normalisation so historical callers keep the exact same output.
  def get(code, locale) when is_atom(code) and code in @errors, do: translate(code, locale)
  def get(code, locale) when is_atom(code) and code in @status_msgids, do: translate(code, locale)

  def get(term, locale), do: term |> Error.from_reason() |> message(locale)

  # -- message selection ------------------------------------------------------

  # Signature failures keep their historical, element-specific wording.
  defp message(%Error{reason: :no_signature, scope: :assertion}, locale),
    do: translate(:missing_assertion_signature, locale)

  defp message(%Error{reason: :no_signature, scope: :envelope}, locale),
    do: translate(:missing_envelope_signature, locale)

  defp message(%Error{reason: :cert_not_accepted, scope: :assertion}, locale),
    do: translate(:assertion_cert_not_accepted, locale)

  # IdP status: prefer the nested (second-level) code when the IdP sent one,
  # else fall back to the top-level code.
  defp message(%Error{reason: :saml_error} = e, locale) do
    cond do
      msgid = Map.get(@status_msgid_by_atom, e.saml_sub_status) -> translate(msgid, locale)
      e.saml_status == :responder -> translate(:status_responder, locale)
      e.saml_status == :requester -> translate(:invalid_nameid_policy, locale)
      true -> unknown({:saml_error, e.saml_status_uri, e.saml_message}, locale)
    end
  end

  defp message(%Error{reason: reason} = e, locale) do
    cond do
      reason in @errors -> translate(reason, locale)
      msgid = Map.get(@status_msgid_by_atom, reason) -> translate(msgid, locale)
      true -> unknown(e.detail || reason, locale)
    end
  end

  defp unknown(error, locale) do
    Logger.warning("[ExSaml] No error message for code #{inspect(error)}")
    translate(:unknown_error, locale)
  end

  defp translate(code, locale) do
    Gettext.with_locale(ExSaml.Gettext, locale, fn ->
      Gettext.dgettext(ExSaml.Gettext, "errors", Atom.to_string(code))
    end)
  end
end
