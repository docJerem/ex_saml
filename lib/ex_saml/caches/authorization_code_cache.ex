defmodule ExSaml.AuthorizationCodeCache do
  @moduledoc false
  use Nebulex.Cache,
    otp_app: :ex_saml,
    adapter: Nebulex.Adapters.Local

  def ttl, do: :timer.seconds(30)
end
