defmodule ExSaml.Core.Assertion do
  @moduledoc """
  Represents a SAML Assertion element.

  Ported from the Erlang `esaml_assertion` record.

  Beyond the esaml fields:

    * `id` — the assertion's `ID` attribute, the key of the replay check
      (Profiles §4.1.4.5);
    * `audience_restrictions` — the `Audience` values of each
      `Conditions/AudienceRestriction`, one list per element (Core §2.5.1.4).
      `conditions[:audience]` keeps the first value for compatibility;
    * `one_time_use` — whether `Conditions/OneTimeUse` is present (Core §2.5.1.5).
  """

  alias ExSaml.Core.Subject

  defstruct id: "",
            version: "2.0",
            issue_instant: "",
            recipient: "",
            issuer: "",
            subject: %Subject{},
            conditions: [],
            audience_restrictions: [],
            one_time_use: false,
            attributes: [],
            authn: []

  @type t :: %__MODULE__{
          id: String.t(),
          version: String.t(),
          issue_instant: String.t(),
          recipient: String.t(),
          issuer: String.t(),
          subject: Subject.t(),
          conditions: keyword(),
          audience_restrictions: [[String.t()]],
          one_time_use: boolean(),
          attributes: keyword(),
          authn: keyword()
        }
end
