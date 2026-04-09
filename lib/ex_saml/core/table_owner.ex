defmodule ExSaml.Core.TableOwner do
  @moduledoc false
  use GenServer

  @tables [
    :ex_saml_core_assertion_seen,
    :ex_saml_core_privkey_cache,
    :ex_saml_core_certbin_cache,
    :ex_saml_core_idp_meta_cache
  ]

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    for table <- @tables do
      :ets.new(table, [:set, :public, :named_table])
    end

    {:ok, %{}}
  end

  def tables, do: @tables
end
