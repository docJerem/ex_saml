# TODO

Items removed from code during the Credo audit cleanup.

## Audit the SAML nonce (`auth_handler.ex`)

**Previous location:** `ExSaml.AuthHandler.request_idp/2` (line ~43)

**Context:** The nonce is read from an encrypted cookie (`saml_nonce`) or falls back
to `UUID.uuid4()`. It is stored in the `RelayStateCache` alongside the relay state
and later retrieved during `validate_authresp` in `SPHandler`.

**What to audit:**
- Verify that the nonce actually prevents replay attacks (is it checked once and
  discarded?).
- Confirm the encrypted cookie cannot be forged or reused across sessions.
- Ensure the `UUID.uuid4()` fallback is acceptable — it is random but not
  cryptographically tied to the session.

## Session elements have no TTL (`auth_handler.ex`)

**Previous location:** `ExSaml.AuthHandler.request_idp/2` (line ~63)

**Context:** `put_session("relay_state", ...)` and `put_session("idp_id", ...)` are
written to the Plug session without an explicit expiration. The relay state *cache*
entry has a 5-minute TTL, but the session keys themselves persist until the session
expires or is dropped.

**What to do:**
- Evaluate whether stale session keys could cause issues (e.g., a user who never
  completes the SSO flow retains the relay state in their session indefinitely).
- Consider clearing these keys after a successful or failed authentication, or
  enforcing a session-level TTL.
