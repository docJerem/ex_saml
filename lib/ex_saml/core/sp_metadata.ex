defmodule ExSaml.Core.SpMetadata do
  @moduledoc """
  Represents SAML Service Provider metadata.

  Ported from the Erlang `esaml_sp_metadata` record.
  """

  alias ExSaml.Core.{Contact, Org}

  defstruct org: %Org{},
            tech: %Contact{},
            signed_requests: true,
            signed_assertions: true,
            certificate: nil,
            cert_chain: [],
            entity_id: "",
            consumer_location: "",
            logout_location: nil

  @type t :: %__MODULE__{
          org: Org.t(),
          tech: Contact.t(),
          signed_requests: boolean(),
          signed_assertions: boolean(),
          certificate: binary() | nil,
          cert_chain: [binary()],
          entity_id: String.t(),
          consumer_location: String.t(),
          logout_location: String.t() | nil
        }
end
