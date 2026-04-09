defmodule ExSaml.Assertion do
  @moduledoc """
  SAML assertion returned from IDP upon successful user authentication.

  The assertion attributes returned by the IdP are available in `attributes` field
  as a map. Any computed attributes are available in `computed` field as map.

  The attributes can be accessed directly from `attributes` or `computed` maps.
  The `ExSaml.get_attribute/2` function can be used as well. This function will
  first look at the `computed` attributes. If the request attribute is not present there,
  it will check in `attributes` next.
  """

  alias ExSaml.Subject

  require Logger

  @type attr_name_t :: String.t()
  @type attr_value_t :: String.t() | [String.t()]

  defstruct version: "2.0",
            issue_instant: "",
            recipient: "",
            issuer: "",
            subject: %Subject{},
            conditions: %{},
            attributes: %{},
            authn: %{},
            computed: %{},
            idp_id: ""

  @type t :: %__MODULE__{
          version: String.t(),
          issue_instant: String.t(),
          recipient: String.t(),
          issuer: String.t(),
          subject: Subject.t(),
          conditions: map,
          attributes: %{required(attr_name_t()) => attr_value_t()},
          authn: map,
          computed: %{required(attr_name_t()) => attr_value_t()},
          idp_id: String.t()
        }

  def get_from_code(code) do
    case ExSaml.AuthorizationCodeCache.take(code) do
      {idp_id, _} = key ->
        case ExSaml.AssertionCache.get(key) do
          %__MODULE__{attributes: assertion} -> {:ok, {idp_id, assertion}}
          _ -> {:error, assertion: :not_found}
        end

      _ ->
        Logger.info("Authorization code expired")
        {:error, :unauthorized}
    end
  end

  @doc false
  def from_core(%ExSaml.Core.Assertion{} = core) do
    %__MODULE__{
      version: to_string_safe(core.version),
      issue_instant: to_string_safe(core.issue_instant),
      recipient: to_string_safe(core.recipient),
      issuer: to_string_safe(core.issuer),
      subject: Subject.from_core(core.subject),
      conditions: core.conditions |> stringize(),
      attributes: core.attributes |> stringize(),
      authn: core.authn |> stringize()
    }
  end

  defp to_string_safe(val) when is_list(val), do: List.to_string(val)
  defp to_string_safe(val) when is_binary(val), do: val
  defp to_string_safe(_), do: ""

  defp stringize(proplist) do
    proplist
    |> Enum.map(fn
      {k, []} ->
        {to_string(k), ""}

      {k, values} when is_list(values) and is_list(hd(values)) ->
        {to_string(k), Enum.map(values, fn v -> List.to_string(v) end)}

      {k, v} when is_list(v) ->
        {to_string(k), List.to_string(v)}

      {k, v} ->
        {to_string(k), to_string(v)}
    end)
    |> Enum.into(%{})
  end
end
