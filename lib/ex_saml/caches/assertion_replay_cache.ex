defmodule ExSaml.AssertionReplayCache do
  @moduledoc """
  The assertion IDs already consumed, kept until the assertion would be
  rejected as stale anyway (SAML 2.0 Profiles §4.1.4.5).

  `ExSaml.SPHandler` runs this check on every `SAMLResponse`, through
  `ExSaml.Helper.decode_idp_auth_resp/4`. The key is the `Assertion/@ID`
  together with its `Issuer` (the digest of the whole response when the
  assertion has no `ID`); the entry expires at the assertion's earliest
  `NotOnOrAfter` (`SubjectConfirmationData` or `Conditions`, else
  `IssueInstant` + 5 minutes), plus the clock skew.

  Uses the cache module configured via `config :ex_saml, cache: MyApp.Cache`,
  like `ExSaml.RelayStateCache` and `ExSaml.AuthorizationCodeCache`, through
  its `put_new/3`: the first write of an ID wins, atomically for the cache
  adapter. A cache shared by every node (a partitioned or replicated Nebulex
  cache, or a module forwarding to a shared store) detects a replay across
  nodes; a node-local cache only detects it on the node that consumed the
  assertion. A custom cache module must implement `put_new/3` with the
  Nebulex 2 contract: `true` when the key was written, `false` when it exists.

  The outcome goes through `ExSaml.Core.ValidationContext` as the
  `:duplicate` check: enforced by default, logged only when absent from
  `config :ex_saml, :enforced_response_checks`, and always enforced for an
  assertion carrying `Conditions/OneTimeUse` (Core §2.5.1.5).
  """

  alias ExSaml.Core.{Assertion, Saml, SpConfig, ValidationContext}

  @doc """
  A `duplicate_fun` for `ExSaml.Core.Sp.validate_assertion/4` backed by this
  cache, evaluated with the policy and clock of `sp` and `opts` (`:now`).
  """
  @spec duplicate_fun(SpConfig.t(), keyword()) ::
          (Assertion.t(), binary() -> :ok | {:error, :duplicate})
  def duplicate_fun(%SpConfig{} = sp, opts \\ []) do
    fn assertion, digest ->
      check(assertion, digest, ValidationContext.from_sp_config(sp, opts))
    end
  end

  @doc """
  Records the assertion as consumed and returns `:ok`, or, when it already
  was, the verdict of the `:duplicate` check.
  """
  @spec check(Assertion.t(), binary(), ValidationContext.t()) :: :ok | {:error, :duplicate}
  def check(%Assertion{} = assertion, digest, %ValidationContext{} = ctx) do
    key = key(assertion, digest)

    case consume(key, ttl(assertion, ctx)) do
      :ok ->
        :ok

      :duplicate ->
        ctx =
          if assertion.one_time_use,
            do: ValidationContext.always_enforce(ctx, :duplicate),
            else: ctx

        ValidationContext.verdict(ctx, {:error, :duplicate},
          assertion_id: assertion.id,
          issuer: assertion.issuer,
          one_time_use: assertion.one_time_use
        )
    end
  end

  @doc """
  Stores `key` for `ttl` milliseconds unless it is already present. Returns
  `:ok` for the first write and `:duplicate` afterwards.
  """
  @spec consume(term(), pos_integer()) :: :ok | :duplicate
  def consume(key, ttl) do
    if cache().put_new(cache_key(key), true, ttl: ttl), do: :ok, else: :duplicate
  end

  @doc "Whether `key` is currently recorded as consumed."
  @spec consumed?(term()) :: boolean()
  def consumed?(key), do: cache().get(cache_key(key)) != nil

  @doc "The key an assertion is recorded under."
  @spec key(Assertion.t(), binary()) :: term()
  def key(%Assertion{id: id, issuer: issuer}, digest) do
    case to_string(id) do
      "" -> {:digest, digest}
      id -> {:id, issuer |> to_string() |> String.trim(), id}
    end
  end

  # Until the assertion would be rejected as stale, with the clock skew as a
  # margin, and at least one second.
  defp ttl(assertion, ctx) do
    secs = Saml.stale_time(assertion) - ValidationContext.now_secs(ctx) + Saml.clock_skew_secs()
    max(secs, 1) * 1000
  end

  defp cache, do: Application.get_env(:ex_saml, :cache)

  defp cache_key(key), do: {__MODULE__, key}
end
