defmodule ExSaml.Core.LogoutResponse do
  @moduledoc """
  Represents a SAML LogoutResponse message.

  Ported from the Erlang `esaml_logoutresp` record.
  """

  defstruct version: "2.0",
            in_response_to: "",
            issue_instant: "",
            destination: "",
            issuer: "",
            status: :unknown

  @type t :: %__MODULE__{
          version: String.t(),
          in_response_to: String.t(),
          issue_instant: String.t(),
          destination: String.t(),
          issuer: String.t(),
          status: atom()
        }
end
