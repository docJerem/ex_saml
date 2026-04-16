defmodule ExSaml.MixProject do
  use Mix.Project

  @source_url "https://github.com/docJerem/ex_saml"
  @version "1.0.2"

  def project do
    [
      aliases: aliases(),
      app: :ex_saml,
      deps: deps(),
      description: description(),
      dialyzer: [ignore_warnings: ".dialyzer_ignore.exs"],
      elixir: "~> 1.15",
      package: package(),
      preferred_cli_env: preferred_cli_env(),
      source_url: @source_url,
      start_permanent: Mix.env() == :prod,
      test_coverage: [tool: ExCoveralls],
      version: @version
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :xmerl, :crypto, :public_key, :inets],
      mod: {ExSaml.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:elixir_uuid, "~> 1.2"},
      {:excoveralls, "~> 0.18", only: :test, runtime: false},
      {:ex_doc, "~> 0.38", only: :dev, runtime: false},
      {:gettext, ">= 0.26.0"},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:nebulex, "~> 2.6"},
      {:plug, "~> 1.18"},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false},
      {:sweet_xml, "~> 0.7"}
    ]
  end

  defp description do
    """
    SAML 2.0 Service Provider (SP) library for Elixir/Phoenix applications.
    Enables SP-initiated and IdP-initiated SSO, Single Logout, SP metadata generation,
    and multi-IdP support with pluggable assertion storage.
    """
  end

  defp package do
    [
      maintainers: [
        "Jeremie Flandrin"
      ],
      licenses: ["MIT"],
      links: %{
        "Github" => @source_url
      }
    ]
  end

  defp aliases do
    [
      audit: [
        "credo --strict",
        # "deps.audit",
        "deps.unlock --check-unused",
        "dialyzer --format github",
        "format --check-formatted",
        "sobelow --config --skip",
        # Hex does not work in alias
        # so "hex.audit" become:
        &run_hex_audit/1,
        &run_hex_outdated/1
      ]
    ]
  end

  defp preferred_cli_env do
    [
      coveralls: :test,
      "coveralls.detail": :test,
      "coveralls.post": :test,
      "coveralls.html": :test,
      "coveralls.cobertura": :test
    ]
  end

  defp run_hex_audit(_), do: Mix.shell().cmd("mix hex.audit")

  defp run_hex_outdated(_), do: Mix.shell().cmd("mix hex.outdated --within-requirements")
end
