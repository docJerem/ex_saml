defmodule ExSaml.Core.Subject do
  @moduledoc """
  Represents a SAML Subject element within an Assertion.

  Ported from the Erlang `esaml_subject` record. `confirmation_method` is
  `:unknown` when the decoded `SubjectConfirmation` states a method other than
  bearer or none at all; `notbefore` is `SubjectConfirmationData/@NotBefore`
  (`""` when absent).
  """

  defstruct name: "",
            name_qualifier: nil,
            sp_name_qualifier: nil,
            name_format: nil,
            confirmation_method: :bearer,
            notbefore: "",
            notonorafter: "",
            in_response_to: ""

  @type t :: %__MODULE__{
          name: String.t(),
          name_qualifier: String.t() | nil,
          sp_name_qualifier: String.t() | nil,
          name_format: String.t() | nil,
          confirmation_method: :bearer | :unknown,
          notbefore: String.t(),
          notonorafter: String.t(),
          in_response_to: String.t()
        }
end
