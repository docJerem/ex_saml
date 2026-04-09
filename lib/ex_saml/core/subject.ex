defmodule ExSaml.Core.Subject do
  @moduledoc """
  Represents a SAML Subject element within an Assertion.

  Ported from the Erlang `esaml_subject` record.
  """

  defstruct name: "",
            name_qualifier: nil,
            sp_name_qualifier: nil,
            name_format: nil,
            confirmation_method: :bearer,
            notonorafter: "",
            in_response_to: ""

  @type t :: %__MODULE__{
          name: String.t(),
          name_qualifier: String.t() | nil,
          sp_name_qualifier: String.t() | nil,
          name_format: String.t() | nil,
          confirmation_method: :bearer | :unknown,
          notonorafter: String.t(),
          in_response_to: String.t()
        }
end
