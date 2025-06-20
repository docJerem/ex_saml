defmodule ExSaml.ErrorMessages do
  @moduledoc """
  Error messages

  Provide explanation for an error from its error code

  ## Example

      iex(2)> ExSaml.ErrorMessages.get(:bad_audience)
      "Make sure that the entity_id in configuration is correct"

      iex(3)> ExSaml.ErrorMessages.get(:cert_no_accepted)
      "Make sure the Identity Provider metadata XML file you are
      using in the config setting is correct and corresponds to the
      IdP you are attempting to talk to, you get this error if the
      certificate used by the IdP to sign the SAML responses has
      changed and you don't have the updated IdP metadata XML file"

  """
  @status_responder {:saml_error, ~c"urn:oasis:names:tc:SAML:2.0:status:Responder", :undefined}
  @assertion_signature {:assertion, {:error, :no_signature}}
  @assertion_cert_not_accepted {:assertion, {:error, :cert_not_accepted}}
  @envelop_signature {:envelope, {:error, :no_signature}}
  @name_id_errors {:saml_error, ~c"urn:oasis:names:tc:SAML:2.0:status:Requester", :undefined}
  @errors ~w(bad_digest assertion_cert_not_accepted missing_assertion_key bad_audience cert_no_accepted invalid_nameid_policy invalid_nonce missing_assertion_signature missing_envelope_signature status_responder)a

  @doc false
  def get(error, locale \\ "en")

  def get({:error, error}, locale), do: get(error, locale)

  def get(@status_responder, locale),
    do: get(:status_responder, locale)

  def get(@assertion_signature, locale),
    do: get(:missing_assertion_signature, locale)

  def get(@assertion_cert_not_accepted, locale),
    do: get(:assertion_cert_not_accepted, locale)

  def get(@envelop_signature, locale),
    do: get(:missing_envelope_signature, locale)

  def get(@name_id_errors, locale),
    do: get(:invalid_nameid_policy, locale)

  def get(error, locale) when error in @errors do
    Gettext.with_locale(ExSaml.Gettext, locale, fn ->
      Gettext.dgettext(ExSaml.Gettext, "errors", Atom.to_string(error))
    end)
  end

  def get(error, _),
    do:
      raise(
        "Invalid error message code, valid errors are #{inspect(@errors)} got '#{inspect(error)}'"
      )
end
