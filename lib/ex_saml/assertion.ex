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

  alias ExSaml.{AssertionCache, AuthorizationCodeCache, Debug, Subject}

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

  @doc """
  Redeems an authorization code (single use) and returns `{:ok, {idp_id, attributes}}`.

  Returns `{:error, :unauthorized}` when the code is unknown, expired or already
  consumed, and `{:error, assertion: :not_found}` when the code was valid but the
  assertion is no longer in the assertion store. Both cases are traced by
  `ExSaml.Debug` when debug mode is on.
  """
  def get_from_code(code) do
    ctx = Debug.code_context(code) || %{}

    case AuthorizationCodeCache.take(code) do
      {idp_id, _} = key ->
        fetch_assertion(code, key, idp_id, ctx)

      other ->
        Logger.warning("[ExSaml] Authorization code not found or expired: #{inspect(code)}")

        Debug.log(:code_redeemed, %{
          code: code,
          idp_id: ctx[:idp_id],
          debug_id: ctx[:debug_id],
          code_found: false,
          cache_value: other
        })

        {:error, :unauthorized}
    end
  end

  defp fetch_assertion(code, key, idp_id, ctx) do
    base = %{code: code, idp_id: idp_id, debug_id: ctx[:debug_id], assertion_key: key}

    case AssertionCache.get(key) do
      %__MODULE__{attributes: attributes} = assertion ->
        Debug.log(:code_redeemed, fn ->
          Map.merge(base, %{assertion_found: true, assertion: assertion})
        end)

        {:ok, {idp_id, attributes}}

      other ->
        Debug.log(:code_redeemed, Map.merge(base, %{assertion_found: false, cache_value: other}))
        {:error, assertion: :not_found}
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
