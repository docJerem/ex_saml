defmodule ExSaml.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_saml,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {ExSaml.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.18"},
      {:esaml, "~> 4.6"},
      {:sweet_xml, "~> 0.7"},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.38", only: :dev, runtime: false},
      {:elixir_uuid, "~> 1.2"},

      # Cache
      {:nebulex, "~> 2.6"},
      {:gettext, ">= 0.26.0"}
      # Maybe to remove
      # {:cleeck, in_umbrella: true},
    ]
  end
end
