defmodule ExSaml.Core.Response do
  @moduledoc """
  Represents a SAML Response message.

  Ported from the Erlang `esaml_response` record.
  """

  alias ExSaml.Core.Assertion

  defstruct version: "2.0",
            issue_instant: "",
            destination: "",
            issuer: "",
            status: :unknown,
            assertion: %Assertion{}

  @type t :: %__MODULE__{
          version: String.t(),
          issue_instant: String.t(),
          destination: String.t(),
          issuer: String.t(),
          status: atom(),
          assertion: Assertion.t()
        }
end
