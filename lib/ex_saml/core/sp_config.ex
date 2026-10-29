defmodule ExSaml.Core.SpConfig do
  @moduledoc """
  Represents a SAML Service Provider configuration.

  Ported from the Erlang `esaml_sp` record. Holds all configuration
  needed for SP operations including keys, certificates, and signing options.
  """

  alias ExSaml.Core.{Contact, Org}

  defstruct org: %Org{},
            tech: %Contact{},
            key: nil,
            certificate: nil,
            cert_chain: [],
            sp_sign_requests: false,
            idp_signs_assertions: true,
            idp_signs_envelopes: true,
            idp_signs_logout_requests: true,
            idp_signs_logout_responses: true,
            sp_sign_metadata: false,
            trusted_fingerprints: [],
            trusted_certs: [],
            metadata_uri: "",
            consume_uri: "",
            logout_uri: nil,
            encrypt_mandatory: false,
            allow_rsa_1_5_key_transport: false,
            allow_unsigned_cbc: false,
            allow_unsigned: false,
            entity_id: nil,
            idp_entity_id: nil,
            idp_id: nil

  @type t :: %__MODULE__{
          org: Org.t(),
          tech: Contact.t(),
          key: term() | nil,
          certificate: binary() | nil,
          cert_chain: [binary()],
          sp_sign_requests: boolean(),
          idp_signs_assertions: boolean(),
          idp_signs_envelopes: boolean(),
          idp_signs_logout_requests: boolean(),
          idp_signs_logout_responses: boolean(),
          sp_sign_metadata: boolean(),
          trusted_fingerprints: [String.t() | binary()],
          trusted_certs: [binary()],
          metadata_uri: String.t(),
          consume_uri: String.t(),
          logout_uri: String.t() | nil,
          encrypt_mandatory: boolean(),
          allow_rsa_1_5_key_transport: boolean(),
          allow_unsigned_cbc: boolean(),
          allow_unsigned: boolean(),
          entity_id: String.t() | nil,
          idp_entity_id: String.t() | nil,
          idp_id: String.t() | nil
        }

  @doc """
  The SP entity id used as the assertion audience and as the issuer of the
  requests we generate, falling back to the metadata URI when none is configured.
  """
  @spec entity_id(t()) :: String.t() | charlist()
  def entity_id(%__MODULE__{entity_id: nil, metadata_uri: metadata_uri}), do: metadata_uri
  def entity_id(%__MODULE__{entity_id: entity_id}), do: entity_id
end
