defmodule ExSaml.UI do
  @moduledoc """

  """
  def value(:entity_id, %{saml_service_provider_id: entity_id, sp_id: nil}),
    do: entity_id

  def value(:entity_id, %{sp_id: sp_id}), do: sp_id

  def value(:acs_url, %{id: idp_id}),
    do: ExSaml.get_acs_uri(saml_host(), saml_scope(), idp_id)

  def value(:slo_url, %{id: idp_id}),
    do: ExSaml.get_slo_uri(saml_host(), saml_scope(), idp_id)

  def value(:slo_response_url, %{id: idp_id}),
    do: ExSaml.get_slo_response_uri(saml_host(), saml_scope(), idp_id)

  def value(:sp_metadata_url, %{id: idp_id}),
    do: ExSaml.get_metadata_uri(saml_host(), saml_scope(), idp_id)

  def labels(:"saml.adfs") do
    [
      acs_url: ["Relying party SAML 2.0 SSO service URL"],
      entity_id: ["Relying party trust identifier"],
      slo_url: ["SLO Trusted URL"],
      slo_response_url: ["SLO Response URL"]
    ]
  end

  def labels(:"saml.azure_ad") do
    [
      entity_id: ["Entity ID"],
      acs_url: ["URL Assertion Consumer Service"],
      slo_response_url: ["SLO Response URL"]
    ]
  end

  def labels(:"saml.google") do
    [acs_url: ["ACS URL"], entity_id: ["Entity ID"]]
  end

  def labels(:"saml.ibm_security_verify") do
    [
      entity_id: ["Entity ID"],
      acs_url: ["Assertion Consumer Service URL"],
      # sp_sso_url: ["Service provider single sign-on URL"],
      slo_response_url: ["Single Logout URL"]
    ]
  end

  def labels(:"saml.keycloak") do
    [
      entity_id: ["Client ID"],
      acs_url: ["Valid redirect URIs", "Master SAML Processing URL"],
      slo_response_url: ["Logout Service POST Binding URL"]
    ]
  end

  def labels(:"saml.okta") do
    [
      entity_id: ["Audience URI (SP Entity ID)", "SP Issuer"],
      acs_url: ["Single sign on URL"],
      slo_response_url: ["Single Logout URL"]
    ]
  end

  def labels(:"saml.onelogin") do
    [
      entity_id: ["Audience (EntityID)"],
      acs_url: [
        "Recipient",
        "ACS (Consumer) URL Validator",
        "ACS (Consumer) URL"
      ],
      slo_response_url: ["Single Logout URL"]
    ]
  end

  def labels(:"saml.ping_federate") do
    [
      entity_id: ["Partner Entity ID", "Connection name"],
      acs_url: ["ACS URL"],
      slo_url: ["SLO Endpoint URL"],
      slo_response_url: ["SLO Response URL"]
    ]
  end

  def labels(:"saml.ping_one") do
    [
      acs_url: ["ACS URLs"],
      entity_id: ["Entity ID"],
      slo_url: ["SLO endpoint"],
      slo_response_url: ["SLO Response endpoint"]
    ]
  end

  def labels(:"saml.lemon_ldap") do
    [
      sp_metadata_url: ["SP Metdata URL"]
    ]
  end

  def labels(_provider_type) do
    [
      entity_id: ["Entity ID"],
      acs_url: ["ACS URL"]
    ]
  end

  defp saml_scope, do: "/api"
  defp saml_host, do: Application.get_env(Cleeck.Umbrella, :saml_url)
end
