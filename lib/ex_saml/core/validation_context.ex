defmodule ExSaml.Core.ValidationContext do
  @moduledoc """
  Everything the assertion checks need, plus the policy that decides whether a
  failed check rejects the response or only logs.

  ## Why a struct

  The checks required by SAML 2.0 Core / Profiles need values that live in the
  SP configuration (the IdP's `entityID`, our ACS URL) rather than in the
  assertion. Threading them as positional arguments makes
  `Core.Saml.validate_assertion/3` grow one argument per check, and two adjacent
  `String.t() | nil` parameters are indistinguishable to both a reader and to
  Dialyzer — swapping the issuer and the destination would type-check. A struct
  turns a misspelled field into a compile error and keeps the call sites stable
  as further checks land.

  ## Checks

  | Check | Error | Reads |
  |---|---|---|
  | Issuer matches the IdP `entityID` | `:bad_issuer` | `Response/Issuer`, `Assertion/Issuer` |
  | `InResponseTo` matches our AuthnRequest | `:bad_in_response_to` | `SubjectConfirmationData/@InResponseTo` |
  | `Destination` matches the ACS URL | `:bad_destination` | `Response/@Destination` |
  | Session still valid | `:session_expired` | `AuthnStatement/@SessionNotOnOrAfter` |
  | Assertion not replayed | `:duplicate` | `Assertion/@ID` |
  | Subject confirmation is bearer | `:bad_subject_confirmation` | `SubjectConfirmation/@Method` |

  ## Enforce or warn

  `config :ex_saml, :enforced_response_checks, [...]` lists the checks that
  reject. Anything absent from the list is evaluated and logged but does not
  change the outcome, which is how a check can be observed against real IdP
  traffic before it starts refusing logins.

  The default enforces the checks that cannot plausibly reject a conformant
  response. `:bad_destination` and `:duplicate` are deliberately absent: the
  first depends on our ACS URL matching byte for byte what the IdP was
  configured with, the second changes what happens when a browser replays a
  callback. Both need evidence from the warn logs before they can be turned on.

  Setting the list to `[]` downgrades every check to log-only — the rollback
  lever if an enforcing check turns out to reject real traffic.
  """

  require Logger

  alias ExSaml.Core.SpConfig

  defstruct audience: "",
            destination: nil,
            enforce: nil,
            idp_entity_id: nil,
            idp_id: nil,
            recipient: ""

  @type check ::
          :bad_destination
          | :bad_in_response_to
          | :bad_issuer
          | :bad_subject_confirmation
          | :duplicate
          | :session_expired

  @type t :: %__MODULE__{
          audience: String.t() | charlist(),
          destination: String.t() | charlist() | nil,
          enforce: [check()] | nil,
          idp_entity_id: String.t() | nil,
          idp_id: String.t() | nil,
          recipient: String.t() | charlist()
        }

  @all_checks [
    :bad_destination,
    :bad_in_response_to,
    :bad_issuer,
    :bad_subject_confirmation,
    :duplicate,
    :session_expired
  ]

  @default_enforced [
    :bad_in_response_to,
    :bad_issuer,
    :bad_subject_confirmation,
    :session_expired
  ]

  @doc "Builds a context from the SP configuration for one IdP."
  @spec from_sp_config(SpConfig.t()) :: t()
  def from_sp_config(%SpConfig{} = sp) do
    %__MODULE__{
      audience: SpConfig.entity_id(sp),
      destination: sp.consume_uri,
      enforce: enforced_checks(),
      idp_entity_id: sp.idp_entity_id,
      idp_id: sp.idp_id,
      recipient: sp.consume_uri
    }
  end

  @doc """
  The checks that reject rather than warn.

  Read at call time rather than at compile time so the policy can be changed
  without recompiling the library, and so `Credo.Check.Warning.ApplicationConfigInModuleAttribute`
  stays happy.
  """
  @spec enforced_checks() :: [check()]
  def enforced_checks do
    case Application.get_env(:ex_saml, :enforced_response_checks, @default_enforced) do
      :all -> @all_checks
      list when is_list(list) -> list
      _ -> @default_enforced
    end
  end

  @doc "Every check this module knows about, enforced or not."
  @spec all_checks() :: [check()]
  def all_checks, do: @all_checks

  @doc """
  Turns a check result into an outcome, according to the enforce policy.

  `details` is a keyword list of context for the warn line — typically
  `expected:` and `actual:`. Pass values verbatim: the point of the log is to
  let a human classify a mismatch, and normalising first destroys the evidence.
  """
  @spec verdict(t(), :ok | {:error, check()}, keyword()) :: :ok | {:error, check()}
  def verdict(_ctx, :ok, _details), do: :ok

  def verdict(%__MODULE__{} = ctx, {:error, check} = error, details) do
    if check in (ctx.enforce || enforced_checks()) do
      error
    else
      Logger.warning(warn_line(ctx, check, details))
      :ok
    end
  end

  @doc """
  Emits the warn line for a check without ever rejecting, and returns `:ok`.

  For observations that must not change the outcome whatever the policy says —
  an attribute the IdP sent in a shape we cannot evaluate, say. Use `verdict/3`
  for anything that should be able to reject once it has been proven.
  """
  @spec warn(t(), check(), keyword()) :: :ok
  def warn(%__MODULE__{} = ctx, check, details) do
    Logger.warning(warn_line(ctx, check, details))
    :ok
  end

  # One grep-able shape for every check, so a single log query covers the whole
  # population and `check=` partitions it. `enforced=false` is part of the line
  # because after a check is switched on it stops being emitted at all — a
  # non-zero count afterwards means the switch did not take.
  defp warn_line(ctx, check, details) do
    fields =
      [check: check, enforced: false, idp_id: ctx.idp_id]
      |> Kernel.++(details)
      |> Enum.map_join(" ", fn {k, v} -> "#{k}=#{inspect(printable(v))}" end)

    "[ExSaml] saml_validation " <> fields
  end

  defp printable(value) when is_list(value) do
    if List.ascii_printable?(value), do: to_string(value), else: value
  end

  defp printable(value), do: value
end
