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

  alias ExSaml.{AssertionCache, AuthorizationCodeCache, Debug, Error, Subject}

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
  Exchanges an authorization code (single use) for `{:ok, {idp_id, attributes}}`.

  On failure returns `{:error, %ExSaml.Error{step: :code_exchange}}` with `reason`
  `:authorization_code_not_found` (unknown, expired or already used code) or
  `:assertion_not_found` (valid code, but the assertion is gone from the
  assertion store). Both are traced by `ExSaml.Debug` when debug mode is on,
  and the flow's capture is promoted so the `SAMLResponse` is kept.
  """
  @spec get_from_code(term()) :: {:ok, {binary(), map()}} | {:error, Error.t()}
  def get_from_code(code) do
    ctx = Debug.code_context(code) || %{}

    case AuthorizationCodeCache.take(code) do
      {idp_id, _} = key ->
        fetch_assertion(code, key, idp_id, ctx)

      # Map minted by `ExSaml.SPHandler`; `trace_id` is optional so that codes
      # written by an older node during a rolling deploy are still honoured.
      %{ex_saml_assertion_key: {idp_id, _} = key} = payload ->
        fetch_assertion(
          code,
          key,
          idp_id,
          Map.merge(ctx, %{trace_id: payload[:trace_id] || ctx[:trace_id]}),
          payload
        )

      other ->
        # A missed code is worthless as a credential, but keep logs consistent
        # with the :steps redaction: only a prefix, enough to correlate.
        Logger.warning("[ExSaml] Authorization code not found or expired: #{code_prefix(code)}")

        Debug.log(:code_exchanged, %{
          code: code,
          idp_id: ctx[:idp_id],
          trace_id: ctx[:trace_id],
          code_found: false,
          cache_value: other
        })

        {:error,
         Error.new(%{
           reason: :authorization_code_not_found,
           step: :code_exchange,
           idp_id: ctx[:idp_id],
           trace_id: ctx[:trace_id]
         })}
    end
  end

  defp fetch_assertion(code, key, idp_id, ctx, payload \\ nil) do
    trace_id = ctx[:trace_id]
    base = %{code: code, idp_id: idp_id, trace_id: trace_id, assertion_key: key, payload: payload}

    case AssertionCache.get(key) do
      %__MODULE__{attributes: attributes} = assertion ->
        # The consumer's process has no debug context: pass the IdP explicitly
        # so per-IdP debug also records successful exchanges.
        Debug.log(:code_exchanged, idp_id, fn ->
          Map.merge(base, %{assertion_found: true, assertion: assertion})
        end)

        {:ok, {idp_id, attributes}}

      other ->
        Debug.log(:code_exchanged, Map.merge(base, %{assertion_found: false, cache_value: other}))

        error =
          Error.new(%{
            reason: :assertion_not_found,
            step: :code_exchange,
            idp_id: idp_id,
            trace_id: trace_id
          })

        Debug.promote(trace_id, error, :assertion_not_found)
        {:error, error}
    end
  end

  defp code_prefix(code) when is_binary(code), do: String.slice(code, 0, 6) <> "…"
  defp code_prefix(code), do: inspect(code)

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
