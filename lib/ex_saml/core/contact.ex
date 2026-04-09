defmodule ExSaml.Core.Contact do
  @moduledoc """
  Represents a SAML ContactPerson element.

  Ported from the Erlang `esaml_contact` record.
  """

  defstruct name: "",
            email: ""

  @type t :: %__MODULE__{
          name: String.t(),
          email: String.t()
        }
end
