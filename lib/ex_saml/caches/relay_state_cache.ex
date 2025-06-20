defmodule ExSaml.RelayStateCache do
  @moduledoc false
  use Nebulex.Cache,
    otp_app: :ex_saml,
    adapter: Nebulex.Adapters.Local

  def ttl, do: :timer.minutes(5)
end
