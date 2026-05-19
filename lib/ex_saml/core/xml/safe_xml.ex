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

  ## Functions

    * `scan/1` returns `{:ok, root}` or `{:error, :invalid_xml}`.
    * `scan!/1` returns the root element or raises `ArgumentError`. Use it
      when the surrounding code already runs inside a `try`/`rescue` or
      when a malformed payload should propagate as an exception.
  """

  @scan_opts [namespace_conformant: true, allow_entities: false, quiet: true]

  @type xml :: term()

  @doc """
  Parse `xml` with `:xmerl_scan` using the hardened option set.

  Accepts either a UTF-8 binary or a charlist. Returns the parsed root on
  success or `{:error, :invalid_xml}` on any parse failure (`rescue`d
  exception or `catch`-able exit).
  """
  @spec scan(binary() | charlist()) :: {:ok, xml()} | {:error, :invalid_xml}
  def scan(xml) when is_binary(xml), do: xml |> :binary.bin_to_list() |> scan()

  def scan(xml) when is_list(xml) do
    {root, _rest} = :xmerl_scan.string(xml, @scan_opts)
    {:ok, root}
  rescue
    _ -> {:error, :invalid_xml}
  catch
    _kind, _reason -> {:error, :invalid_xml}
  end

  @doc """
  Same as `scan/1` but raises `ArgumentError` on parse failure and returns
  the parsed root directly.
  """
  @spec scan!(binary() | charlist()) :: xml()
  def scan!(xml) do
    case scan(xml) do
      {:ok, root} -> root
      {:error, reason} -> raise ArgumentError, "invalid XML: #{inspect(reason)}"
    end
  end
end
