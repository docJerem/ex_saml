defmodule ExSaml.Error do
  @moduledoc """
  A sign-in failure, redeemable once by `error_id`.

  This is the failure-side counterpart of the authorization `code`: when the
  assertion consumer service cannot complete a sign-in, `ExSaml.SPHandler`
  stores an `%ExSaml.Error{}` in `ExSaml.ErrorCache` and redirects to the target
  URL with `?error_id=<id>`. The consumer redeems it with `get_from_id/1`:

      def callback(conn, %{"error_id" => error_id}) do
        case ExSaml.Error.get_from_id(error_id) do
          {:ok, %ExSaml.Error{} = error} ->
            Logger.warning("SAML sign-in failed", reason: inspect(error.reason))
            render(conn, "error.html", message: ExSaml.ErrorMessages.get(error))

          {:error, :not_found} ->
            # expired or already consumed
            redirect(conn, to: "/")
        end
      end

  ## Fields

    * `reason` — the error term produced by the library (unchanged public
      vocabulary, e.g. `:bad_audience`, `{:assertion, {:error, :bad_digest}}`,
      `{:saml_error, status_uri, message}`, `:invalid_relay_state`)
    * `step` — where the flow stopped: `:idp_lookup`, `:decode`,
      `:validate_authresp`, `:target_url` or `:unexpected` (an exception was rescued)
    * `flow` — `:sp_initiated`, `:idp_initiated` or `nil` when unknown
    * `idp_id`, `relay_state`, `node`, `at` — correlation data
    * `saml_status` / `saml_sub_status` — the IdP `StatusCode` atoms from
      `ExSaml.Core.StatusCode` when `reason` is a `{:saml_error, _, _}`
    * `debug_id` — key of the `ExSaml.Debug` report for this flow (when debug was on)
    * `details` — the full `ExSaml.Debug.report/1` when debug was on, else `nil`
  """

  alias ExSaml.{Core.StatusCode, Debug, ErrorCache, Helper, State}

  defstruct reason: nil,
            step: nil,
            flow: nil,
            idp_id: nil,
            relay_state: nil,
            saml_status: nil,
            saml_sub_status: nil,
            debug_id: nil,
            node: nil,
            at: nil,
            details: nil

  @type step :: :idp_lookup | :decode | :validate_authresp | :target_url | :unexpected
  @type t :: %__MODULE__{
          reason: term(),
          step: step() | nil,
          flow: :sp_initiated | :idp_initiated | nil,
          idp_id: binary() | nil,
          relay_state: binary() | nil,
          saml_status: StatusCode.t() | :unknown | nil,
          saml_sub_status: StatusCode.t() | :unknown | nil,
          debug_id: binary() | nil,
          node: node(),
          at: DateTime.t(),
          details: Debug.report() | nil
        }

  @doc """
  Builds an error from the given attributes, filling `node`, `at`, the SAML
  status atoms and, when debug is enabled for the IdP, `details`.
  """
  @spec new(map() | keyword()) :: t()
  def new(attrs) do
    attrs = Map.new(attrs)
    reason = Map.get(attrs, :reason)
    idp_id = Map.get(attrs, :idp_id)
    debug_id = Map.get(attrs, :debug_id)

    {saml_status, saml_sub_status} = saml_statuses(reason)

    %__MODULE__{
      reason: reason,
      step: Map.get(attrs, :step),
      flow: Map.get(attrs, :flow),
      idp_id: idp_id,
      relay_state: Map.get(attrs, :relay_state),
      saml_status: saml_status,
      saml_sub_status: saml_sub_status,
      debug_id: debug_id,
      node: node(),
      at: DateTime.utc_now(),
      details: if(Debug.enabled?(idp_id), do: Debug.report(debug_id))
    }
  end

  @doc """
  Stores the error under a fresh random id and returns `{error_id, error}`.
  """
  @spec issue(t()) :: {binary(), t()}
  def issue(%__MODULE__{} = error) do
    error_id = State.gen_id()
    ErrorCache.put_new!(error_id, error)
    {error_id, error}
  end

  @doc """
  Redeems an `error_id` (single use). Returns `{:error, :not_found}` when the
  id is unknown, expired or already consumed.
  """
  @spec get_from_id(binary()) :: {:ok, t()} | {:error, :not_found}
  def get_from_id(error_id) when is_binary(error_id) do
    case ErrorCache.take(error_id) do
      %__MODULE__{} = error -> {:ok, error}
      _ -> {:error, :not_found}
    end
  end

  def get_from_id(_), do: {:error, :not_found}

  @doc "Appends `error_id=<id>` to a URL, preserving any existing query string."
  @spec append_error_id(binary(), binary()) :: binary()
  def append_error_id(url, error_id), do: Helper.append_query_param(url, "error_id", error_id)

  # `ExSaml.Core.Sp.check_status_value/4` records the nested StatusCode in the
  # process Logger metadata so it can be surfaced here without changing the
  # public `{:saml_error, status, message}` tuple.
  defp saml_statuses({:saml_error, status, _message}) do
    sub_status =
      case Logger.metadata()[:ex_saml_saml_sub_status] do
        nil -> nil
        sub -> sub
      end

    {StatusCode.to_atom(status), sub_status}
  end

  defp saml_statuses(_), do: {nil, nil}
end
