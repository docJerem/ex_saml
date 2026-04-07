defmodule ExSaml.Core do
  @moduledoc """
  Pure Elixir SAML 2.0 core library.

  Conversion of the Erlang library to Elixir to improve maintainability. Esaml
  is an abandoned library.

  Provides XML canonicalization (C14N), XML digital signatures (XMLDSig),
  SAML protocol encoding/decoding, Service Provider operations,
  and HTTP binding support.
  """
  @version "4.6.0"

  def version, do: @version
end
