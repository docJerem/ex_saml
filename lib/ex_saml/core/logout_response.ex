defmodule ExSaml.Core.LogoutResponse do
  @moduledoc """
  Represents a SAML LogoutResponse message.

  Ported from the Erlang `esaml_logoutresp` record.
  """

  defstruct version: "2.0",
            issue_instant: "",
            destination: "",
            issuer: "",
            status: :unknown

  @type t :: %__MODULE__{
          version: String.t(),
          issue_instant: String.t(),
          destination: String.t(),
          issuer: String.t(),
          status: atom()
        }
end
