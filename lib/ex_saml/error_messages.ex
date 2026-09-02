defmodule ExSaml.ErrorMessages do
  @moduledoc """
  Error messages

  Provide a human-readable explanation for an error produced by the library,
  from its error code, its `{:error, code}` tuple or an `%ExSaml.Error{}`.

  ## Example

      iex(2)> ExSaml.ErrorMessages.get(:bad_audience)
      "Make sure that the entity_id in configuration is correct"

      iex(3)> ExSaml.ErrorMessages.get(:cert_no_accepted)
      "Make sure the Identity Provider metadata XML file you are
      using in the config setting is correct and corresponds to the
      IdP you are attempting to talk to, you get this error if the
      certificate used by the IdP to sign the SAML responses has
      changed and you don't have the updated IdP metadata XML file"

  Unknown codes never raise: they yield the generic `unknown_error` message and
  are logged at `:warning` level so the raw code is not lost.
  """

  require Logger

  alias ExSaml.Core.StatusCode

  @signature_errors ~w(no_signature bad_digest bad_signature cert_not_accepted missing_certificate multiple_signatures insecure_algorithm unsupported_algorithm)a

  # Historical codes kept for compatibility with existing consumers.
  @legacy_errors ~w(assertion_cert_not_accepted missing_assertion_key cert_no_accepted invalid_nameid_policy invalid_nonce missing_assertion_signature missing_envelope_signature status_responder)a

  # Reasons produced by the library on the sign-in path.
  @flow_errors ~w(bad_saml bad_assertion bad_version bad_recipient bad_audience too_early stale_assertion duplicate invalid_response missing_saml_response idp_initiated_not_allowed invalid_target_url invalid_relay_state invalid_idp_id unknown_idp exception access_denied unknown_error)a

  @errors Enum.uniq(@legacy_errors ++ @flow_errors ++ @signature_errors)

  # gettext msgids for second-level SAML statuses, e.g. `:saml_status_authn_failed`.
  # Built once at compile time from the closed catalogue, so no atom is ever
  # created from runtime input.
  @status_msgid_by_atom Map.new(StatusCode.second_level(), &{&1, :"saml_status_#{&1}"})
  @status_msgids Map.values(@status_msgid_by_atom)

  @doc "Every error code that has a dedicated message."
  @spec codes() :: [atom()]
  def codes, do: @errors ++ @status_msgids

  @doc false
  def get(error, locale \\ "en")

  def get(%ExSaml.Error{reason: reason, saml_sub_status: sub_status}, locale)
      when not is_nil(sub_status) and sub_status != :unknown do
    case reason do
      {:saml_error, _, _} -> translate(status_code(sub_status), locale)
      _ -> get(reason, locale)
    end
  end

  def get(%ExSaml.Error{reason: reason}, locale), do: get(reason, locale)

  def get({:error, error}, locale), do: get(error, locale)

  # IdP status errors: prefer the nested (second-level) code when the IdP sent
  # one, else fall back to the top-level code.
  def get({:saml_error, status, _message}, locale) do
    sub_status = Logger.metadata()[:ex_saml_saml_sub_status]

    cond do
      sub_status && sub_status != :unknown -> translate(status_code(sub_status), locale)
      StatusCode.to_atom(status) == :responder -> get(:status_responder, locale)
      StatusCode.to_atom(status) == :requester -> get(:invalid_nameid_policy, locale)
      true -> get(:unknown_error, locale)
    end
  end

  def get({:assertion, {:error, :no_signature}}, locale),
    do: get(:missing_assertion_signature, locale)

  def get({:assertion, {:error, :cert_not_accepted}}, locale),
    do: get(:assertion_cert_not_accepted, locale)

  def get({:envelope, {:error, :no_signature}}, locale),
    do: get(:missing_envelope_signature, locale)

  # Covers :missing_certificate (#51) and every other Dsig.verify/2 reason.
  def get({:assertion, {:error, error}}, locale), do: get(error, locale)
  def get({:envelope, {:error, error}}, locale), do: get(error, locale)

  def get({:invalid_response, _}, locale), do: get(:invalid_response, locale)
  def get({:unknown_idp, _}, locale), do: get(:unknown_idp, locale)
  def get({:exception, _}, locale), do: get(:exception, locale)
  def get([assertion: :not_found], locale), do: get(:missing_assertion_key, locale)
  def get(:unauthorized, locale), do: get(:access_denied, locale)

  def get(error, locale) when is_atom(error) do
    cond do
      error in @errors -> translate(error, locale)
      error in @status_msgids -> translate(error, locale)
      StatusCode.second_level?(error) -> translate(status_code(error), locale)
      true -> unknown(error, locale)
    end
  end

  def get(error, locale), do: unknown(error, locale)

  defp unknown(error, locale) do
    Logger.warning("[ExSaml] No error message for code #{inspect(error)}")
    translate(:unknown_error, locale)
  end

  defp translate(code, locale) do
    Gettext.with_locale(ExSaml.Gettext, locale, fn ->
      Gettext.dgettext(ExSaml.Gettext, "errors", Atom.to_string(code))
    end)
  end

  # gettext msgid for a second-level SAML status, e.g. `:authn_failed` ->
  # `:saml_status_authn_failed`.
  defp status_code(atom), do: Map.get(@status_msgid_by_atom, atom, :unknown_error)
end
