defmodule ExSaml.Core.StatusCode do
  @moduledoc """
  Catalogue of the SAML 2.0 `StatusCode` values (SAML 2.0 Core §3.2.2.2).

  A `<samlp:Status>` carries a top-level `<samlp:StatusCode>` whose `Value` is
  one of four URIs (`Success`, `Requester`, `Responder`, `VersionMismatch`).
  When the request failed, the IdP MAY nest a second-level `<samlp:StatusCode>`
  that carries the actionable reason (`AuthnFailed`, `InvalidNameIDPolicy`,
  `UnknownPrincipal`, …). This module maps every URI defined by the spec to an
  atom and back.

      iex> ExSaml.Core.StatusCode.to_atom("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
      :authn_failed

      iex> ExSaml.Core.StatusCode.to_uri(:responder)
      "urn:oasis:names:tc:SAML:2.0:status:Responder"

      iex> ExSaml.Core.StatusCode.to_atom("urn:example:not-a-status")
      :unknown
  """

  @prefix "urn:oasis:names:tc:SAML:2.0:status:"

  @top_level [
    success: "Success",
    requester: "Requester",
    responder: "Responder",
    version_mismatch: "VersionMismatch"
  ]

  @second_level [
    authn_failed: "AuthnFailed",
    invalid_attr_name_or_value: "InvalidAttrNameOrValue",
    invalid_nameid_policy: "InvalidNameIDPolicy",
    no_authn_context: "NoAuthnContext",
    no_available_idp: "NoAvailableIDP",
    no_passive: "NoPassive",
    no_supported_idp: "NoSupportedIDP",
    partial_logout: "PartialLogout",
    proxy_count_exceeded: "ProxyCountExceeded",
    request_denied: "RequestDenied",
    request_unsupported: "RequestUnsupported",
    request_version_deprecated: "RequestVersionDeprecated",
    request_version_too_high: "RequestVersionTooHigh",
    request_version_too_low: "RequestVersionTooLow",
    resource_not_recognized: "ResourceNotRecognized",
    too_many_responses: "TooManyResponses",
    unknown_attr_profile: "UnknownAttrProfile",
    unknown_principal: "UnknownPrincipal",
    unsupported_binding: "UnsupportedBinding"
  ]

  @all @top_level ++ @second_level

  @type top_level :: :success | :requester | :responder | :version_mismatch
  @type second_level ::
          :authn_failed
          | :invalid_attr_name_or_value
          | :invalid_nameid_policy
          | :no_authn_context
          | :no_available_idp
          | :no_passive
          | :no_supported_idp
          | :partial_logout
          | :proxy_count_exceeded
          | :request_denied
          | :request_unsupported
          | :request_version_deprecated
          | :request_version_too_high
          | :request_version_too_low
          | :resource_not_recognized
          | :too_many_responses
          | :unknown_attr_profile
          | :unknown_principal
          | :unsupported_binding
  @type t :: top_level() | second_level()

  @doc "All status atoms defined by the spec, top level first."
  @spec all() :: [t()]
  def all, do: Keyword.keys(@all)

  @doc "Top-level status atoms."
  @spec top_level() :: [top_level()]
  def top_level, do: Keyword.keys(@top_level)

  @doc "Second-level status atoms."
  @spec second_level() :: [second_level()]
  def second_level, do: Keyword.keys(@second_level)

  @doc """
  Maps a status URI (binary or charlist) to its atom. Returns `:unknown` for
  anything outside the spec catalogue, including `nil`.
  """
  @spec to_atom(binary() | charlist() | nil) :: t() | :unknown
  def to_atom(nil), do: :unknown
  def to_atom(uri) when is_list(uri), do: uri |> List.to_string() |> to_atom()

  for {atom, suffix} <- @all do
    def to_atom(unquote(@prefix <> suffix)), do: unquote(atom)
  end

  def to_atom(uri) when is_binary(uri), do: :unknown

  @doc """
  Maps a status atom to its URI. Raises `ArgumentError` for an atom outside the
  catalogue.
  """
  @spec to_uri(t()) :: binary()
  for {atom, suffix} <- @all do
    def to_uri(unquote(atom)), do: unquote(@prefix <> suffix)
  end

  def to_uri(other) do
    raise ArgumentError, "unknown SAML status code #{inspect(other)}"
  end

  @doc "Whether the atom is one of the four top-level status codes."
  @spec top_level?(atom()) :: boolean()
  def top_level?(atom), do: Keyword.has_key?(@top_level, atom)

  @doc "Whether the atom is one of the second-level status codes."
  @spec second_level?(atom()) :: boolean()
  def second_level?(atom), do: Keyword.has_key?(@second_level, atom)
end
