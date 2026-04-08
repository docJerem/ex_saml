[
  # Defensive catch-all in `consume_signin_response/1`'s `with` else block.
  # Provably unreachable today, kept intentionally so the auth endpoint fails
  # closed (HTTP 403) if a future change introduces a new return shape.
  # See lib/ex_saml/sp_handler.ex for the inline rationale.
  ~r/lib\/ex_saml\/sp_handler\.ex:95:.*pattern_match_cov/,

  # `stale_time/1` step 1: the `if t == :none or secs < t` expression is
  # tautologically true here because `t` is provably `:none` at this point
  # (variable shadowing inside the `case` body — the new `t` is only bound
  # after the case finishes). The structure is preserved verbatim from the
  # upstream esaml `stale_time/1` to keep behavioral parity and ease future
  # backports. See lib/ex_saml/core/saml.ex around line 798.
  ~r/lib\/ex_saml\/core\/saml\.ex:803:28:pattern_match/,
  ~r/lib\/ex_saml\/core\/saml\.ex:803:54:pattern_match/
]
