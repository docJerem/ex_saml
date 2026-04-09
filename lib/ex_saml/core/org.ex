defmodule ExSaml.Core.Org do
  @moduledoc """
  Represents a SAML Organization element.

  Ported from the Erlang `esaml_org` record.
  """

  defstruct name: "",
            displayname: "",
            url: ""

  @type t :: %__MODULE__{
          name: String.t() | [{atom(), String.t()}],
          displayname: String.t() | [{atom(), String.t()}],
          url: String.t() | [{atom(), String.t()}]
        }
end
