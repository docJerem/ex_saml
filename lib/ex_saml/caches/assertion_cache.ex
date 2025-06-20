defmodule ExSaml.AssertionCache do
  @moduledoc false
  use Nebulex.Cache,
    otp_app: :ex_saml,
    adapter: Nebulex.Adapters.Local
end
