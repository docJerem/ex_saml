[
  # Defensive catch-alls in `consume_signin_response/1` and
  # `consume_signin_response/2` `with` else blocks. Provably unreachable today,
  # kept intentionally so the auth endpoint fails closed (HTTP 403 / error
  # tuple) if a future change introduces a new return shape.
  # See lib/ex_saml/sp_handler.ex for the inline rationale.
  ~r/lib\/ex_saml\/sp_handler\.ex:108:.*pattern_match_cov/,
  ~r/lib\/ex_saml\/sp_handler\.ex:144:.*pattern_match_cov/
]
