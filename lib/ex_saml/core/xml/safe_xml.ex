defmodule ExSaml.Core.Xml.SafeXml do
  @moduledoc """
  Single entry point for parsing untrusted SAML/XML payloads with `:xmerl_scan`.

  All calls go through this module so that the XXE-safe options
  (`allow_entities: false`, `namespace_conformant: true`) and the
  binary→charlist conversion are applied **once**, in one place. Callers do
  not pass scan options — they cannot weaken the defaults.

  Centralising the wrapper means a future hardening change (new xmerl option,
  stricter limits, alternative parser) is a one-file diff. It also
  centralises the binary→charlist conversion that previously had to be
  patched at every call site (cf. UTF-8 SAMLResponse handling).

  ## Error reporting hook

  An arity-1 function may be configured to receive parse-failure context.
  Typical use: forward to a SIEM / OCSF pipeline.

      config :ex_saml, :safe_xml,
        on_error: &MyApp.SIEM.report_xml_error/1

  The handler is invoked **after** the `{:error, :invalid_xml}` tuple is
  produced and receives a map:

      %{
        reason: :invalid_xml,
        kind: :error | :exit | :throw,
        payload: Exception.t() | term()
      }

  Any exception raised by the handler is silently caught — the handler must
  never be able to mask the original parse failure or alter the caller's
  control flow.
  """

  @scan_opts [namespace_conformant: true, allow_entities: false, quiet: true]

  @type xml :: term()
  @type error_context :: %{
          required(:reason) => :invalid_xml,
          required(:kind) => :error | :exit | :throw,
          required(:payload) => Exception.t() | term()
        }

  @doc """
  Parse `xml` with `:xmerl_scan` using the hardened option set.

  Accepts either a UTF-8 binary or a charlist. Returns the parsed root on
  success or `{:error, :invalid_xml}` on any parse failure.

  Invokes the configured `:on_error` hook (if any) before returning the
  error tuple.
  """
  @spec scan(binary() | charlist()) :: {:ok, xml()} | {:error, :invalid_xml}
  def scan(xml) when is_binary(xml), do: xml |> :binary.bin_to_list() |> scan()

  def scan(xml) when is_list(xml) do
    {root, _rest} = :xmerl_scan.string(xml, @scan_opts)
    {:ok, root}
  rescue
    e ->
      notify(%{reason: :invalid_xml, kind: :error, payload: e})
      {:error, :invalid_xml}
  catch
    :exit, reason ->
      notify(%{reason: :invalid_xml, kind: :exit, payload: reason})
      {:error, :invalid_xml}

    :throw, value ->
      notify(%{reason: :invalid_xml, kind: :throw, payload: value})
      {:error, :invalid_xml}
  end

  # ---------------------------------------------------------------------------
  # Error reporting hook
  # ---------------------------------------------------------------------------

  defp notify(context) do
    case Application.get_env(:ex_saml, :safe_xml, [])[:on_error] do
      fun when is_function(fun, 1) ->
        safe_invoke(fun, context)

      _ ->
        :ok
    end
  end

  defp safe_invoke(fun, context) do
    fun.(context)
    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end
end
