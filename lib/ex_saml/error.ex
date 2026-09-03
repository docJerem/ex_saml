defmodule ExSaml.Error do
  @moduledoc """
  The single error shape exposed by the library.

  Every public function that can fail returns `{:error, %ExSaml.Error{}}`:
  `ExSaml.SPHandler.consume_signin_response/2`, `ExSaml.Error.get_from_id/1`,
  `ExSaml.Assertion.get_from_code/1` and `ExSaml.Debug.replay/2`. Internally,
  `ExSaml.Core.*` keep returning plain tuples; `from_reason/2` is the one place
  where those tuples are normalised, **without losing any of the information
  they carried**.

  ## Identifier: `trace_id`

  Every sign-in flow has a `trace_id` (the `RelayState` for SP-initiated flows,
  a fresh id otherwise), whether debug is on or off. It is the identifier of
  the error, the value of the `?error_id=` redirect parameter, the key of the
  `ExSaml.Debug` trace and capture, and the id carried by the authorization
  code payload. Show it to the end user and log it: it is the one key the
  support team needs.

  ## Looking up an error at the callback

      def callback(conn, %{"error_id" => error_id}) do
        case ExSaml.Error.get_from_id(error_id) do
          {:ok, %ExSaml.Error{trace_id: trace_id} = error} ->
            Logger.warning("SAML sign-in failed", trace_id: trace_id, reason: error.reason)
            render(conn, "error.html", message: ExSaml.ErrorMessages.get(error), trace_id: trace_id)

          {:error, %ExSaml.Error{reason: :error_not_found}} ->
            redirect(conn, to: "/")
        end
      end

  ## Fields

    * `trace_id` — the identifier (see above); `nil` only when an authorization
      code could not be found at all
    * `reason` — **always an atom**, from a closed catalogue (see
      `ExSaml.ErrorMessages.codes/0` and the guide)
    * `scope` — `:envelope` or `:assertion` for signature failures (which
      element failed), else `nil`
    * `step` — `:idp_lookup`, `:decode`, `:validate_authresp`, `:target_url`,
      `:code_exchange` (`ExSaml.Assertion.get_from_code/1`), `:error_lookup`
      (`get_from_id/1`), `:replay` (`ExSaml.Debug.replay/2`) or `:unexpected`
    * `flow` — `:sp_initiated`, `:idp_initiated` or `nil`
    * `idp_id`, `relay_state`, `node`, `at` — correlation data
    * `saml_status`, `saml_status_uri`, `saml_sub_status`, `saml_message` — the
      IdP `Status` when `reason` is `:saml_error` (`ExSaml.Core.StatusCode` atoms,
      the raw top-level URI, and the `StatusMessage` text)
    * `detail` — free text carried by the original error: the exception message
      for `:exception`, the decoding error for `:invalid_response`, …
    * `trace` — the `ExSaml.Debug` trace of the flow when debug was on, else `nil`

  ## Legacy tuples

  `to_legacy/1` rebuilds the tuple the library returned before 2.0
  (`{:envelope, {:error, :no_signature}}`, `{:saml_error, uri, message}`, …)
  for consumers migrating incrementally.
  """

  alias ExSaml.{Core.StatusCode, Debug, ErrorCache, State}

  defstruct trace_id: nil,
            reason: nil,
            scope: nil,
            step: nil,
            flow: nil,
            idp_id: nil,
            relay_state: nil,
            saml_status: nil,
            saml_status_uri: nil,
            saml_sub_status: nil,
            saml_message: nil,
            detail: nil,
            trace: nil,
            node: nil,
            at: nil

  @type step ::
          :idp_lookup
          | :decode
          | :validate_authresp
          | :target_url
          | :code_exchange
          | :error_lookup
          | :replay
          | :unexpected
  @type t :: %__MODULE__{
          trace_id: binary() | nil,
          reason: atom(),
          scope: :envelope | :assertion | nil,
          step: step() | nil,
          flow: :sp_initiated | :idp_initiated | nil,
          idp_id: binary() | nil,
          relay_state: binary() | nil,
          saml_status: StatusCode.t() | :unknown | nil,
          saml_status_uri: binary() | nil,
          saml_sub_status: StatusCode.t() | :unknown | nil,
          saml_message: binary() | nil,
          detail: binary() | nil,
          trace: Debug.trace() | nil,
          node: node() | nil,
          at: DateTime.t() | nil
        }

  # ---------------------------------------------------------------------------
  # Building
  # ---------------------------------------------------------------------------

  @doc """
  Normalises any error term produced by the library into an `%ExSaml.Error{}`,
  merging `attrs` (step, flow, idp_id, relay_state, trace_id, …).

  Nothing carried by the legacy tuples is dropped:

      iex> ExSaml.Error.from_reason({:envelope, {:error, :no_signature}})
      %ExSaml.Error{reason: :no_signature, scope: :envelope, ...}

      iex> ExSaml.Error.from_reason({:saml_error, ~c"urn:oasis:names:tc:SAML:2.0:status:Responder", ~c"denied"})
      %ExSaml.Error{reason: :saml_error, saml_status: :responder, saml_message: "denied", ...}

      iex> ExSaml.Error.from_reason({:invalid_response, "%ArgumentError{...}"})
      %ExSaml.Error{reason: :invalid_response, detail: "%ArgumentError{...}", ...}
  """
  @spec from_reason(term(), map() | keyword()) :: t()
  def from_reason(reason, attrs \\ %{})

  def from_reason(%__MODULE__{} = error, attrs), do: struct(error, Map.new(attrs))

  def from_reason({:error, reason}, attrs), do: from_reason(reason, attrs)

  def from_reason({scope, {:error, reason}}, attrs) when scope in [:envelope, :assertion] do
    reason |> from_reason(attrs) |> Map.put(:scope, scope)
  end

  def from_reason({:saml_error, status, message}, attrs) do
    {saml_message, detail} =
      case message do
        nil -> {nil, nil}
        :malformed -> {nil, "malformed StatusMessage"}
        m -> {to_string(m), nil}
      end

    base(:saml_error, attrs)
    |> Map.merge(%{
      saml_status: StatusCode.to_atom(status),
      saml_status_uri: status && to_string(status),
      saml_sub_status: Logger.metadata()[:ex_saml_saml_sub_status],
      saml_message: saml_message,
      detail: detail
    })
  end

  def from_reason({:invalid_response, detail}, attrs),
    do: base(:invalid_response, attrs) |> Map.put(:detail, to_string(detail))

  def from_reason({:exception, detail}, attrs),
    do: base(:exception, attrs) |> Map.put(:detail, to_string(detail))

  def from_reason({:unknown_idp, idp_id}, attrs),
    do: base(:unknown_idp, attrs) |> Map.put(:idp_id, idp_id)

  def from_reason([assertion: :not_found], attrs), do: base(:assertion_not_found, attrs)

  def from_reason(reason, attrs) when is_atom(reason) and not is_nil(reason),
    do: base(reason, attrs)

  def from_reason(other, attrs),
    do: base(:unknown_error, attrs) |> Map.put(:detail, inspect(other))

  defp base(reason, attrs) do
    attrs = Map.new(attrs)

    %__MODULE__{
      reason: reason,
      node: node(),
      at: DateTime.utc_now()
    }
    |> struct(Map.drop(attrs, [:reason]))
  end

  @doc """
  Builds an error from attributes (`reason` may be a legacy tuple) and attaches
  the `ExSaml.Debug` trace when debug is enabled for the IdP.
  """
  @spec new(t() | map() | keyword()) :: t()
  def new(%__MODULE__{} = error), do: attach_trace(error)

  def new(attrs) do
    attrs = Map.new(attrs)
    attrs |> Map.get(:reason) |> from_reason(Map.delete(attrs, :reason)) |> attach_trace()
  end

  defp attach_trace(%__MODULE__{} = error) do
    if Debug.enabled?(error.idp_id) and is_nil(error.trace),
      do: %{error | trace: Debug.trace(error.trace_id)},
      else: error
  end

  @doc """
  Stores the error under its `trace_id` (single use) so the consumer can look
  it up with `get_from_id/1`. Generates a `trace_id` when the error has none.

  A flow can fail more than once under the same `trace_id` — the browser
  re-submitting the IdP form after "back" replays the same `RelayState` — so
  the latest failure overwrites the previous one instead of raising.
  """
  @spec issue(t()) :: t()
  def issue(%__MODULE__{} = error) do
    error = %{error | trace_id: error.trace_id || State.gen_id()}
    ErrorCache.put(error.trace_id, error)
    error
  end

  @doc """
  Looks up an `error_id` (the `trace_id`) and consumes it (single use). Returns
  `{:error, %ExSaml.Error{reason: :error_not_found}}` when the id is unknown,
  expired or already consulted.
  """
  @spec get_from_id(term()) :: {:ok, t()} | {:error, t()}
  def get_from_id(error_id) when is_binary(error_id) do
    case ErrorCache.take(error_id) do
      %__MODULE__{} = error -> {:ok, error}
      _ -> {:error, base(:error_not_found, %{step: :error_lookup, detail: error_id})}
    end
  end

  def get_from_id(other),
    do: {:error, base(:error_not_found, %{step: :error_lookup, detail: inspect(other)})}

  @session_text_limit 512

  @doc """
  The copy of the error written to the legacy `ex_saml_error` session entry:
  without the trace, and with the free-text fields (`detail`, `saml_message`)
  capped at #{@session_text_limit} bytes so the cookie session can never
  overflow. The full error stays available through `get_from_id/1`.
  """
  @spec for_session(t()) :: t()
  def for_session(%__MODULE__{} = error) do
    %{
      error
      | trace: nil,
        detail: truncate(error.detail),
        saml_message: truncate(error.saml_message)
    }
  end

  defp truncate(nil), do: nil

  defp truncate(text) when byte_size(text) <= @session_text_limit, do: text
  defp truncate(text) when is_binary(text), do: cut(text, @session_text_limit) <> "…"

  # Cuts at a byte limit without splitting a UTF-8 character.
  defp cut(text, limit) do
    head = binary_part(text, 0, limit)
    if String.valid?(head), do: head, else: cut(text, limit - 1)
  end

  @doc "Appends `error_id=<trace_id>` to a URL, preserving any existing query string."
  @spec append_error_id(binary(), binary()) :: binary()
  def append_error_id(url, trace_id),
    do: ExSaml.RouterUtil.append_query(url, "error_id", trace_id)

  # ---------------------------------------------------------------------------
  # Legacy
  # ---------------------------------------------------------------------------

  @doc """
  Rebuilds the pre-2.0 error term for consumers migrating incrementally.

      iex> ExSaml.Error.to_legacy(%ExSaml.Error{reason: :bad_digest, scope: :assertion})
      {:assertion, {:error, :bad_digest}}
  """
  @spec to_legacy(t()) :: term()
  def to_legacy(%__MODULE__{reason: reason, scope: scope}) when scope in [:envelope, :assertion],
    do: {scope, {:error, reason}}

  def to_legacy(%__MODULE__{reason: :saml_error} = e) do
    uri = e.saml_status_uri || (e.saml_status && StatusCode.to_uri(e.saml_status)) || ""
    message = if e.saml_message, do: String.to_charlist(e.saml_message)
    {:saml_error, String.to_charlist(uri), message}
  end

  def to_legacy(%__MODULE__{reason: :invalid_response, detail: d}), do: {:invalid_response, d}
  def to_legacy(%__MODULE__{reason: :exception, detail: d}), do: {:exception, d}
  def to_legacy(%__MODULE__{reason: :unknown_idp, idp_id: id}), do: {:unknown_idp, id}
  def to_legacy(%__MODULE__{reason: :assertion_not_found}), do: [assertion: :not_found]
  def to_legacy(%__MODULE__{reason: :authorization_code_not_found}), do: :unauthorized
  def to_legacy(%__MODULE__{reason: reason}), do: reason
end
