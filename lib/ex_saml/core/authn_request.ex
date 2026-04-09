defmodule ExSaml.Core.AuthnRequest do
  @moduledoc """
  Represents a SAML AuthnRequest message.

  Ported from the Erlang `esaml_authnreq` record.
  """

  defstruct version: "2.0",
            issue_instant: "",
            destination: "",
            issuer: "",
            name_format: nil,
            consumer_location: ""

  @type t :: %__MODULE__{
          version: String.t(),
          issue_instant: String.t(),
          destination: String.t(),
          issuer: String.t(),
          name_format: String.t() | nil,
          consumer_location: String.t()
        }
end
