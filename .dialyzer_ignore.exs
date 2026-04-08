[
  # Defensive catch-all in `consume_signin_response/1`'s `with` else block.
  # Provably unreachable today, kept intentionally so the auth endpoint fails
  # closed (HTTP 403) if a future change introduces a new return shape.
  # See lib/ex_saml/sp_handler.ex for the inline rationale.
  ~r/lib\/ex_saml\/sp_handler\.ex:95:.*pattern_match_cov/
]
