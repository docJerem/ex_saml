defmodule Mix.Tasks.Security.CheckRelease do
  @shortdoc "Run pre-release security checks for ExSaml"
  @moduledoc """
  Scans the codebase for known unsafe patterns specific to SAML/XML processing.

  Checks:

    * `xmerl_scan.string` calls without `allow_entities: false` (XXE)
    * `signature_props` without a catch-all clause (crash on unknown algorithm)

  ## Usage

      mix security.check_release
  """

  use Mix.Task

  @lib_path "lib"
  @self_path "lib/mix/tasks/security.check_release.ex"

  @impl Mix.Task
  def run(_args) do
    Mix.shell().info("Running ExSaml pre-release security checks...\n")

    findings =
      source_files()
      |> Enum.flat_map(&check_xxe/1)

    algo_findings = check_signature_props_catchall()

    all = findings ++ algo_findings

    case all do
      [] ->
        Mix.shell().info("All checks passed.")

      _ ->
        Enum.each(all, fn {file, line, message} ->
          Mix.shell().error("  #{file}:#{line} — #{message}")
        end)

        Mix.raise("Security check failed: #{length(all)} issue(s) found.")
    end
  end

  defp source_files do
    @lib_path
    |> Path.join("**/*.ex")
    |> Path.wildcard()
    |> Enum.reject(&(&1 == @self_path))
  end

  defp check_xxe(path) do
    content = File.read!(path)
    lines = String.split(content, "\n")

    lines
    |> Enum.with_index(1)
    |> Enum.filter(fn {line, _} -> String.contains?(line, ":xmerl_scan.string") end)
    |> Enum.reject(fn {_line, line_number} ->
      # Check next 3 lines for allow_entities: false (handles multiline formatting)
      lines
      |> Enum.slice(line_number - 1, 4)
      |> Enum.join("\n")
      |> String.contains?("allow_entities: false")
    end)
    |> Enum.map(fn {_line, line_number} ->
      {path, line_number, "xmerl_scan.string without allow_entities: false (XXE risk)"}
    end)
  end

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
end
