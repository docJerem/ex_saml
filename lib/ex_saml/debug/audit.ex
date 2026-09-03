defmodule ExSaml.Debug.Audit do
  @moduledoc false

  # One log line per debug-API request.
  #
  # Registered as a `before_send` callback so it fires exactly once and knows
  # the status the request actually ended on, including the 4xx a plug halted
  # with — which is the half worth auditing.

  require Logger

  alias ExSaml.Debug.Access

  @doc "Registers the audit callback for this request."
  def attach(conn, %Access{} = opts) do
    Plug.Conn.register_before_send(conn, fn conn -> log(conn, opts) end)
  end

  @doc "Marks this request as having handed over personal data."
  def pii(conn), do: Plug.Conn.put_private(conn, :ex_saml_debug_pii, true)

  defp log(conn, %Access{} = opts) do
    entry = %{
      method: conn.method,
      path: path(conn),
      actor: conn.private[:ex_saml_debug_actor] || "unknown",
      idp_id: conn.params["idp_id"],
      trace_id: conn.params["trace_id"],
      status: conn.status,
      pii: conn.private[:ex_saml_debug_pii] == true
    }

    Logger.log(opts.audit_level, fn -> line(entry) end)
    sink(opts.audit_sink, entry)

    conn
  end

  defp line(entry) do
    [
      "[ExSaml.DebugRouter] #{entry.method} #{entry.path}",
      "actor=#{entry.actor}",
      if(entry.idp_id, do: "idp_id=#{entry.idp_id}"),
      if(entry.trace_id, do: "trace_id=#{entry.trace_id}"),
      "status=#{entry.status}",
      "pii=#{entry.pii}"
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  defp path(conn), do: "/" <> Enum.join(conn.script_name ++ conn.path_info, "/")

  defp sink(nil, _entry), do: :ok

  defp sink({mod, fun}, entry) do
    apply(mod, fun, [entry])
    :ok
  rescue
    error ->
      Logger.warning("[ExSaml.DebugRouter] audit sink raised: #{inspect(error)}")
      :ok
  catch
    _, _ -> :ok
  end

  defp sink(_other, _entry), do: :ok
end
