defmodule ExSaml.State.ETS do
  @moduledoc """
  Stores SAML assertion in ETS.

  This provider creates an ETS table (during initialization) to keep the
  authenticated SAML assertions from IdP. The ETS table name in the
  configuration is optional.

  ## Options

  +   `:table` - ETS table name (optional)
                 Value must be an atom

  Do not rely on how the state is stored in the ETS table.

  ## Configuration Example

      config :ex_saml, ExSaml.State,
        opts: [table: :my_ets_table]

  This can be used as an example when creating custom stores based on
  redis, memcached, database etc.
  """

  alias ExSaml.Assertion

  @behaviour ExSaml.State.Store

  @assertions_table :ex_saml_assertions_table

  @impl ExSaml.State.Store
  def init(opts) do
    assertions_table = Keyword.get(opts, :table, @assertions_table)

    if is_atom(assertions_table) == false do
      raise "ExSaml.State.ETS table name must be an atom: #{inspect(assertions_table)}"
    end

    if :ets.info(assertions_table) == :undefined do
      :ets.new(assertions_table, [:set, :public, :named_table])
    end

    assertions_table
  end

  @impl ExSaml.State.Store
  def get_assertion(_conn, assertion_key, assertions_table) do
    case :ets.lookup(assertions_table, assertion_key) do
      [{^assertion_key, %Assertion{} = assertion}] -> validate_assertion_expiry(assertion)
      _ -> nil
    end
  end

  @impl ExSaml.State.Store
  def put_assertion(conn, assertion_key, assertion, assertions_table) do
    :ets.insert(assertions_table, {assertion_key, assertion})
    conn
  end

  @impl ExSaml.State.Store
  def delete_assertion(conn, assertion_key, assertions_table) do
    :ets.delete(assertions_table, assertion_key)
    conn
  end

  defp validate_assertion_expiry(
         %Assertion{subject: %{notonorafter: not_on_or_after}} = assertion
       ) do
    now = DateTime.utc_now()

    case DateTime.from_iso8601(not_on_or_after) do
      {:ok, not_on_or_after, _} ->
        if DateTime.compare(now, not_on_or_after) == :lt, do: assertion, else: nil

      _ ->
        nil
    end
  end
end
