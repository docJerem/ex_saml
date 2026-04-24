defmodule Mix.Tasks.Security.CheckRelease do
  @shortdoc "Run pre-release security checks for ExSaml"
  @moduledoc """
  Scans the codebase for known unsafe patterns specific to SAML/XML processing.

  Errors block the release. Warnings are acknowledged risks that require review.

  ### Errors (block release)

    * XXE — `xmerl_scan.string` calls without `allow_entities: false`
    * XXE — `xmerl_scan.string` calls without `namespace_conformant: true`
    * Algorithm — `signature_props` without a catch-all clause
    * Algorithm — signing with `:rsa_sha1` (weak hash)

  ### Warnings (review before release)

    * Certificate — `check_fingerprints(_, :any)` accepts any cert
    * Open redirect — RelayState used in redirect without URL validation
    * CSRF — unsolicited SAML responses accepted without target URL restriction
    * Comment injection — NameID/attribute extraction without comment stripping

  ## Usage

      mix security.check_release
  """

  use Mix.Task

  @lib_path "lib"
  @self_path "lib/mix/tasks/security.check_release.ex"

  @impl Mix.Task
  def run(_args) do
    Mix.shell().info("Running ExSaml pre-release security checks...\n")

    errors =
      List.flatten([
        run_file_checks(),
        check_signature_props_catchall(),
        check_sign_with_sha1()
      ])

    warnings =
      List.flatten([
        check_fingerprints_any(),
        check_relay_state_open_redirect(),
        check_unsolicited_response_target(),
        check_comment_injection()
      ])

    print_results("error", errors)
    print_results("warning", warnings)
    print_summary(errors, warnings)

    if errors != [] do
      Mix.raise("Security check failed: #{length(errors)} error(s) found.")
    end
  end

  defp print_results(_label, []), do: :ok

  defp print_results(label, findings) do
    Enum.each(findings, fn {file, line, message} ->
      Mix.shell().error("  [#{label}] #{file}:#{line} — #{message}")
    end)
  end

  defp print_summary(errors, warnings) do
    Mix.shell().info("")

    case {errors, warnings} do
      {[], []} ->
        Mix.shell().info("All checks passed.")

      {[], _} ->
        Mix.shell().info("No errors. #{length(warnings)} warning(s) — review before release.")

      _ ->
        :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp source_files do
    @lib_path
    |> Path.join("**/*.ex")
    |> Path.wildcard()
    |> Enum.reject(&(&1 == @self_path))
  end

  defp read_lines(path), do: path |> File.read!() |> String.split("\n")

  defp window(lines, line_number, size) do
    lines |> Enum.slice(line_number - 1, size) |> Enum.join("\n")
  end

  # ---------------------------------------------------------------------------
  # ERRORS — Per-file checks (XXE + namespace_conformant)
  # ---------------------------------------------------------------------------

  defp run_file_checks do
    source_files()
    |> Enum.flat_map(fn path ->
      check_xxe(path) ++ check_namespace_conformant(path)
    end)
  end

  defp check_xxe(path) do
    lines = read_lines(path)

    lines
    |> Enum.with_index(1)
    |> Enum.filter(fn {line, _} -> String.contains?(line, ":xmerl_scan.string") end)
    |> Enum.reject(fn {_line, n} ->
      String.contains?(window(lines, n, 4), "allow_entities: false")
    end)
    |> Enum.map(fn {_line, n} ->
      {path, n, "xmerl_scan.string without allow_entities: false (XXE risk)"}
    end)
  end

  defp check_namespace_conformant(path) do
    lines = read_lines(path)

    lines
    |> Enum.with_index(1)
    |> Enum.filter(fn {line, _} -> String.contains?(line, ":xmerl_scan.string") end)
    |> Enum.reject(fn {_line, n} ->
      String.contains?(window(lines, n, 4), "namespace_conformant: true")
    end)
    |> Enum.map(fn {_line, n} ->
      {path, n, "xmerl_scan.string without namespace_conformant: true (namespace confusion risk)"}
    end)
  end

  # ---------------------------------------------------------------------------
  # ERRORS — Algorithm checks
  # ---------------------------------------------------------------------------

  defp check_signature_props_catchall do
    dsig_path = Path.join(@lib_path, "ex_saml/core/xml/dsig.ex")

    if File.exists?(dsig_path) do
      content = File.read!(dsig_path)

      if Regex.match?(~r/def signature_props\(_/, content) do
        []
      else
        [{dsig_path, 0, "signature_props has no catch-all clause (crash on unknown algorithm)"}]
      end
    else
      []
    end
  end

  defp check_sign_with_sha1 do
    dsig_path = Path.join(@lib_path, "ex_saml/core/xml/dsig.ex")

    if File.exists?(dsig_path) do
      lines = read_lines(dsig_path)

      lines
      |> Enum.with_index(1)
      |> Enum.filter(fn {line, _} ->
        Regex.match?(~r/Dsig\.sign\(.*:rsa_sha1/, line) ||
          Regex.match?(~r/sign\(.*xmldsig#rsa-sha1/, line)
      end)
      |> Enum.map(fn {_line, n} ->
        {dsig_path, n, "signing with RSA-SHA1 (weak algorithm, use RSA-SHA256+)"}
      end)
    else
      []
    end
  end

  # ---------------------------------------------------------------------------
  # WARNINGS — Certificate validation
  # ---------------------------------------------------------------------------

  defp check_fingerprints_any do
    dsig_path = Path.join(@lib_path, "ex_saml/core/xml/dsig.ex")

    if File.exists?(dsig_path) do
      lines = read_lines(dsig_path)

      lines
      |> Enum.with_index(1)
      |> Enum.filter(fn {line, _} ->
        Regex.match?(~r/check_fingerprints\(.*,\s*:any\)/, line)
      end)
      |> Enum.map(fn {_line, n} ->
        {dsig_path, n,
         "check_fingerprints(_, :any) accepts any certificate " <>
           "(ensure this is never reachable with production config)"}
      end)
    else
      []
    end
  end

  # ---------------------------------------------------------------------------
  # WARNINGS — Open redirect via RelayState
  # ---------------------------------------------------------------------------

  defp check_relay_state_open_redirect do
    handler_path = Path.join(@lib_path, "ex_saml/sp_handler.ex")

    if File.exists?(handler_path) do
      lines = read_lines(handler_path)

      lines
      |> Enum.with_index(1)
      |> Enum.filter(fn {line, _} ->
        Regex.match?(~r/redirect\(.*start-from:/, line)
      end)
      |> Enum.map(fn {_line, n} ->
        {handler_path, n,
         "RelayState-derived URL used in redirect — verify URL is validated " <>
           "against allowed_target_urls or a whitelist"}
      end)
    else
      []
    end
  end

  # ---------------------------------------------------------------------------
  # WARNINGS — Unsolicited SAML response (IdP-initiated) target URL restriction
  # ---------------------------------------------------------------------------

  defp check_unsolicited_response_target do
    handler_path = Path.join(@lib_path, "ex_saml/sp_handler.ex")

    if File.exists?(handler_path) do
      content = File.read!(handler_path)
      lines = read_lines(handler_path)

      has_target_url_check =
        Regex.match?(~r/allowed_target_urls.*relay_state/, content)

      if has_target_url_check do
        []
      else
        find_unsolicited_handler_lines(lines, handler_path)
      end
    else
      []
    end
  end

  defp find_unsolicited_handler_lines(lines, handler_path) do
    lines
    |> Enum.with_index(1)
    |> Enum.filter(fn {line, _} ->
      String.contains?(line, "in_response_to: \"\"") &&
        String.contains?(line, "auth_target_url")
    end)
    |> Enum.map(fn {_line, n} ->
      {handler_path, n,
       "IdP-initiated flow accepts relay_state as redirect target " <>
         "without allowed_target_urls check"}
    end)
  end

  # ---------------------------------------------------------------------------
  # WARNINGS — Comment injection in NameID / attributes
  # ---------------------------------------------------------------------------

  defp check_comment_injection do
    saml_path = Path.join(@lib_path, "ex_saml/core/saml.ex")

    if File.exists?(saml_path) do
      content = File.read!(saml_path)
      lines = read_lines(saml_path)

      has_comment_filter =
        Regex.match?(~r/xmlComment|strip_comment|reject_comment/, content)

      lines
      |> Enum.with_index(1)
      |> Enum.filter(fn {line, _} ->
        Regex.match?(~r/xmlText\(.*:value\)/, line) && !has_comment_filter
      end)
      |> Enum.reject(fn {_line, n} ->
        w = window(lines, max(n - 10, 1), 20)
        String.contains?(w, "def to_xml") || String.contains?(w, "# XML generation")
      end)
      |> Enum.map(fn {_line, n} ->
        {saml_path, n,
         "xmlText value extracted without explicit XML comment filtering " <>
           "(potential comment injection in NameID/attributes)"}
      end)
    else
      []
    end
  end
end
