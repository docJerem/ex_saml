defmodule ExSaml.Subject do
  @moduledoc """
  The subject in a SAML 2.0 Assertion.

  This is part of the `ExSaml.Assertion` struct. The `name` field in this struct should not
  be used in any UI directly. It might be a temporary randomly generated
  ID from IdP. `ExSaml` internally uses this to deal with IdP initiated logout requests.

  If an authentication request was sent from `ExSaml` (SP initiated), the SAML response
  is expected to include the original request ID. This ID is made available in
  `ExSaml.Subject.in_response_to`.

  If the authentication request originated from the IDP (IDP initiated), there won't
  be a `ExSaml` request ID associated with it. The `ExSaml.Subject.in_response_to`
  will be an empty string in that case.
  """

  defstruct name: "",
            name_qualifier: :undefined,
            sp_name_qualifier: :undefined,
            name_format: :undefined,
            confirmation_method: :bearer,
            notonorafter: "",
            in_response_to: ""

  @type t :: %__MODULE__{
          name: String.t(),
          name_qualifier: :undefined | String.t(),
          sp_name_qualifier: :undefined | String.t(),
          name_format: :undefined | String.t(),
          confirmation_method: atom,
          notonorafter: String.t(),
          in_response_to: String.t()
        }

  @doc false
  def from_core(%ExSaml.Core.Subject{} = core) do
    %__MODULE__{
      name: to_string_safe(core.name),
      name_qualifier: nil_to_undefined(core.name_qualifier),
      sp_name_qualifier: nil_to_undefined(core.sp_name_qualifier),
      name_format: nil_to_undefined(core.name_format),
      confirmation_method: core.confirmation_method,
      notonorafter: to_string_safe(core.notonorafter),
      in_response_to: to_string_safe(core.in_response_to)
    }
  end

  @doc false
  def to_core(subject) do
    %ExSaml.Core.Subject{
      name: subject.name,
      name_qualifier: undefined_to_nil(subject.name_qualifier),
      sp_name_qualifier: undefined_to_nil(subject.sp_name_qualifier),
      name_format: undefined_to_nil(subject.name_format),
      confirmation_method: subject.confirmation_method,
      notonorafter: subject.notonorafter,
      in_response_to: subject.in_response_to
    }
  end

  defp to_string_safe(val) when is_list(val), do: List.to_string(val)
  defp to_string_safe(val) when is_binary(val), do: val
  defp to_string_safe(_), do: ""

  defp nil_to_undefined(nil), do: :undefined
  defp nil_to_undefined(val) when is_list(val), do: List.to_string(val)
  defp nil_to_undefined(val), do: val

  defp undefined_to_nil(:undefined), do: nil
  defp undefined_to_nil(val), do: val
end
