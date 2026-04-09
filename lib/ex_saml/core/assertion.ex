defmodule ExSaml.Core.Assertion do
  @moduledoc """
  Represents a SAML Assertion element.

  Ported from the Erlang `esaml_assertion` record.
  """

  alias ExSaml.Core.Subject

  defstruct version: "2.0",
            issue_instant: "",
            recipient: "",
            issuer: "",
            subject: %Subject{},
            conditions: [],
            attributes: [],
            authn: []

  @type t :: %__MODULE__{
          version: String.t(),
          issue_instant: String.t(),
          recipient: String.t(),
          issuer: String.t(),
          subject: Subject.t(),
          conditions: keyword(),
          attributes: keyword(),
          authn: keyword()
        }
end
