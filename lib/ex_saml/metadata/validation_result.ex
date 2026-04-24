defmodule ExSaml.Metadata.ValidationResult do
  @moduledoc """
  Result of a call to `ExSaml.Metadata.validate/1` or `ExSaml.Metadata.validate/2`.

  The struct holds two lists of findings: `errors` (severity `:error`) and
  `warnings` (severity `:warning`). See `t:violation/0` for the shape of an
  individual entry.

  Convention used by `ExSaml.Metadata.validate/2`:

    * `{:ok, %__MODULE__{errors: [], warnings: warnings}}` when no error-level
      violation is found (warnings may still be present).
    * `{:error, %__MODULE__{errors: errors, warnings: warnings}}` when at
      least one error-level violation is found.
    * Any code listed in `:ignore` is removed from both lists.
  """

  defstruct errors: [], warnings: []

  @typedoc """
  A single validation finding.

    * `:code` — stable atom identifier for the rule (e.g. `:invalid_acs_binding`).
    * `:severity` — `:error` for spec violations (and some always-error defaults),
      `:warning` for best-practice findings that are not hard failures by default.
    * `:message` — human-readable description of the violation.
    * `:path` — XPath-like pointer to the offending node, or `nil` for
      document-level violations (e.g. `:invalid_xml`, `:invalid_root_element`)
      that have no meaningful location.
    * `:spec_reference` — free-form reference to the SAML / OASIS section that
      justifies the rule, or `nil` when none applies.
  """
  @type violation :: %{
          code: atom(),
          severity: :error | :warning,
          message: String.t(),
          path: String.t() | nil,
          spec_reference: String.t() | nil
        }

  @type t :: %__MODULE__{
          errors: [violation()],
          warnings: [violation()]
        }

  @doc false
  @spec from_violations([violation()]) :: t()
  def from_violations(violations) when is_list(violations) do
    {errors, warnings} = Enum.split_with(violations, &(&1.severity == :error))
    %__MODULE__{errors: errors, warnings: warnings}
  end
end
