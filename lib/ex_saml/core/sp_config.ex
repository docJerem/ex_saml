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
            sp_sign_metadata: false,
            trusted_fingerprints: [],
            metadata_uri: "",
            consume_uri: "",
            logout_uri: nil,
            encrypt_mandatory: false,
            entity_id: nil

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
          sp_sign_metadata: boolean(),
          trusted_fingerprints: [String.t() | binary()],
          metadata_uri: String.t(),
          consume_uri: String.t(),
          logout_uri: String.t() | nil,
          encrypt_mandatory: boolean(),
          entity_id: String.t() | nil
        }
end
