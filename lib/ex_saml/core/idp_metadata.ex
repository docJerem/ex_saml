defmodule ExSaml.Core.IdpMetadata do
  @moduledoc """
  Represents SAML Identity Provider metadata.

  Ported from the Erlang `esaml_idp_metadata` record.
  """

  alias ExSaml.Core.{Contact, Org}

  defstruct org: %Org{},
            tech: %Contact{},
            signed_requests: true,
            certificate: nil,
            entity_id: "",
            login_location: "",
            logout_location: nil,
            name_format: :unknown

  @type t :: %__MODULE__{
          org: Org.t(),
          tech: Contact.t(),
          signed_requests: boolean(),
          certificate: binary() | nil,
          entity_id: String.t(),
          login_location: String.t(),
          logout_location: String.t() | nil,
          name_format: atom()
        }
end
