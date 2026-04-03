defmodule ExSaml.Core.LogoutRequest do
  @moduledoc """
  Represents a SAML LogoutRequest message.

  Ported from the Erlang `esaml_logoutreq` record.
  """

  defstruct version: "2.0",
            issue_instant: "",
            destination: "",
            issuer: "",
            name: "",
            name_qualifier: nil,
            sp_name_qualifier: nil,
            name_format: nil,
            session_index: "",
            reason: :user

  @type t :: %__MODULE__{
          version: String.t(),
          issue_instant: String.t(),
          destination: String.t(),
          issuer: String.t(),
          name: String.t(),
          name_qualifier: String.t() | nil,
          sp_name_qualifier: String.t() | nil,
          name_format: String.t() | nil,
          session_index: String.t(),
          reason: :user | :admin | :unknown
        }
end
