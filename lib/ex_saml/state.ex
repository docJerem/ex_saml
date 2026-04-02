defmodule ExSaml.State do
  @moduledoc """
  Interface for SAML assertion storage.

  Delegates to the configured store provider (`ExSaml.State.ETS`, `ExSaml.State.Session`,
  or `ExSaml.State.Cache`). Configure the store in your `config.exs`:

      config :ex_saml, ExSaml.State,
        store: ExSaml.State.ETS

  To implement a custom store, see `ExSaml.State.Store`.
  """

  @state_store :state_store

  @doc "Initializes the state store with default options."
  def init(store_provider), do: init(store_provider, [])

  @doc "Initializes the state store with the given options."
  def init(store_provider, opts) do
    opts = store_provider.init(opts)
    Application.put_env(:ex_saml, @state_store, %{provider: store_provider, opts: opts})
  end

  @doc "Retrieves the SAML assertion for the given key from the store."
  def get_assertion(conn, assertion_key) do
    %{provider: store_provider, opts: opts} = Application.get_env(:ex_saml, @state_store)
    store_provider.get_assertion(conn, assertion_key, opts)
  end

  @doc "Stores a SAML assertion with the given key."
  def put_assertion(conn, assertion_key, assertion) do
    %{provider: store_provider, opts: opts} = Application.get_env(:ex_saml, @state_store)
    store_provider.put_assertion(conn, assertion_key, assertion, opts)
  end

  @doc "Removes the SAML assertion for the given key from the store."
  def delete_assertion(conn, assertion_key) do
    %{provider: store_provider, opts: opts} = Application.get_env(:ex_saml, @state_store)
    store_provider.delete_assertion(conn, assertion_key, opts)
  end

  @doc "Generates a cryptographically random URL-safe identifier."
  def gen_id do
    24 |> :crypto.strong_rand_bytes() |> Base.url_encode64()
  end
end
