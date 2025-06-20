defmodule ExSaml.State.Session do
  @moduledoc """
  Stores SAML assertion in Plug session.

  This provider uses Plug session to save the authenticated SAML
  assertions from IdP. The session key name in the configuration is optional.

  ## Options

  +   `:key` - Session key name used when saving the assertion (optional)
               Value is either a binary or an atom

  ## Configuration Example

      config :ex_saml, ExSaml.State,
        store: ExSaml.State.Session,
        opts: [key: :my_assertion]
  """

  alias Plug.Conn
  alias ExSaml.Assertion

  @behaviour ExSaml.State.Store

  @session_key "ex_saml_assertion"

  @impl ExSaml.State.Store
  def init(opts) do
    opts |> Map.new() |> Map.put_new(:key, @session_key)
  end

  @impl ExSaml.State.Store
  def get_assertion(conn, assertion_key, opts) do
    %{key: key} = opts

    case Conn.get_session(conn, key) do
      {^assertion_key, %Assertion{} = assertion} -> validate_assertion_expiry(assertion)
      _ -> nil
    end
  end

  @impl ExSaml.State.Store
  def put_assertion(conn, assertion_key, assertion, opts) do
    %{key: key} = opts
    Conn.put_session(conn, key, {assertion_key, assertion})
  end

  @impl ExSaml.State.Store
  def delete_assertion(conn, _assertion_key, opts) do
    %{key: key} = opts
    Conn.delete_session(conn, key)
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
